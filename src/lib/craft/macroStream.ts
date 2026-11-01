/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/macroStream — v4 Chunked Streaming Decompressor
 *  The Living Canvas Edition (Streaming Path)
 * ═══════════════════════════════════════════════════════════════
 *
 *  SECOND execution path. This does NOT touch `macro()` / `peekMetadata()`
 *  (the gold-standard v1–v3 readers). See docs/streaming-architecture.md and
 *  docs/chunk-format.md.
 *
 *  Pipeline (constant memory — one chunk in flight at a time; v4 only):
 *    file/buffer/stream ─► header ─► decrypt metadata ─►
 *      [loop: read chunk record ─► AES-256-GCM per-chunk decrypt
 *                    ─► decompress independent frame ─► SHA-256]
 *        ─► output stream/file (or collected buffer)
 *
 *  Universal reader: for v1/v2/v3 archives it delegates to the unchanged
 *  `macro()`, so a single call restores ANY .craft archive. Only v4 takes the
 *  streaming decode path.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createHash } from 'crypto';
import { createWriteStream, WriteStream } from 'fs';
import { finished } from 'stream/promises';
import type { FileHandle } from 'fs/promises';
import { Readable } from 'stream';
import {
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  SALT_LENGTH,
  METADATA_ENCRYPTED_FLAG,
  METADATA_LENGTH_MASK,
} from './types';
import { decryptMetadataAsync } from './codec';
import {
  STREAM_VERSION,
  CRYPTO_OVERHEAD,
  StreamMetadata,
  MacroStreamOptions,
  MacroStreamResult,
  decryptChunkSync,
  decompressChunkAsync,
  deriveDataKey,
  readMagicVersion,
  resolveStreamMetaEncryption,
  readExact,
  readBigSize,
} from './streamCore';
import { macro } from './macro';

/** Metadata as parsed from a v4 package (loosely typed JSON). */
interface ParsedMetadata {
  version: number;
  streamingVersion?: number;
  originalName?: string;
  originalSize: number;
  originalMime?: string;
  compressedSize?: number;
  compressionMode?: string;
  compressionStrategyName?: string;
  compressionStrategyKey?: 'zstd' | 'brotli';
  encryptionAlgo?: 'aes-256-gcm';
  originalChecksum: string;
  chunkSize?: number;
  chunkCount?: number;
  metadataEncrypted?: boolean;
  createdAt?: string;
}

/** Byte-at-a-time reader abstraction over a Buffer or a stream. */
type ByteReader = (n: number) => Promise<Buffer>;

/** Minimum passphrase length — parity with `macro()`. */
const MIN_PASSPHRASE_LEN = 12;

// ─────────────────────────────────────────────────────────────
// ByteReader factories
// ─────────────────────────────────────────────────────────────

function bufferReader(buf: Buffer): { read: ByteReader; version: number } {
  if (buf.length < 11) {
    throw new Error('Invalid CRAFT package: too small to contain a valid header.');
  }
  const { version } = readMagicVersion(buf);
  let off = 0; // read cursor starts at the 7-byte magic+version; parseV4Header consumes it
  const read: ByteReader = async (n: number) => {
    if (off + n > buf.length) {
      throw new Error('Invalid CRAFT package: truncated data — attempted to read past end of archive.');
    }
    const b = buf.subarray(off, off + n);
    off += n;
    return b;
  };
  return { read, version };
}

/** A Readable that emits `prefix` bytes first, then the rest of `source`. */
function prependBytes(prefix: Buffer, source: NodeJS.ReadableStream): Readable {
  async function* gen() {
    yield prefix;
    for await (const part of source) yield part;
  }
  return Readable.from(gen());
}

// ─────────────────────────────────────────────────────────────
// Version routing
// ─────────────────────────────────────────────────────────────

/** Read from one opened file using explicit positions, retaining bounded memory. */
function fileReader(file: FileHandle, size: number): ByteReader {
  let position = 0;
  return async (length: number) => {
    if (length < 0 || length > size - position) {
      throw new Error('Invalid CRAFT package: truncated data — attempted to read past end of archive.');
    }
    const buffer = Buffer.alloc(length);
    let total = 0;
    while (total < length) {
      const { bytesRead } = await file.read(buffer, total, length - total, position + total);
      if (bytesRead === 0) {
        throw new Error(`Invalid CRAFT package: stream ended before ${length} bytes could be read (wanted ${length}, got ${total}).`);
      }
      total += bytesRead;
    }
    position += total;
    return buffer;
  };
}

function isLegacy(version: number): boolean {
  return (version >= 1 && version < STREAM_VERSION) || version === 5; // single-file v1–v3 and v5
}

interface SourceIdentity {
  path?: string | Buffer;
  stat: fs.Stats;
}

/** ReadStream exposes its descriptor at runtime, including for fd-backed streams. */
function readStreamDescriptor(stream: fs.ReadStream): number | undefined {
  const fd = (stream as fs.ReadStream & { fd?: number | null }).fd;
  return typeof fd === 'number' ? fd : undefined;
}

/** Refuse to replace the source archive, including through a filesystem alias. */
function assertDistinctFiles(source: SourceIdentity | undefined, output: string): void {
  if (!source) return;
  let same = typeof source.path === 'string' && path.resolve(source.path) === path.resolve(output);
  if (!same) {
    try {
      const destination = fs.statSync(output);
      same = source.stat.ino !== 0 && source.stat.dev === destination.dev && source.stat.ino === destination.ino;
      if (!same && source.path !== undefined) {
        same = fs.realpathSync(source.path) === fs.realpathSync(output);
      }
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  if (same) throw new Error('Output path refers to the input archive; choose a different output path.');
}

/** Restore a single-file package, then publish only after verification succeeds. */
async function decodeSingleFile(input: Buffer, passphrase: string, opts: MacroStreamOptions, source?: SourceIdentity): Promise<MacroStreamResult> {
  const res = await macro(input, passphrase);
  if (!opts.verifyOnly && typeof opts.output === 'string') {
    const output = path.resolve(opts.output);
    assertDistinctFiles(source, output);
    const tempDir = fs.mkdtempSync(path.join(path.dirname(output), `.${path.basename(output)}.crafttmp-restore-`));
    const tempFile = path.join(tempDir, 'data');
    try {
      fs.writeFileSync(tempFile, res.buffer, { flag: 'wx', mode: 0o600 });
      if (opts.force) {
        assertDistinctFiles(source, output);
        fs.renameSync(tempFile, output);
      } else {
        try {
          fs.linkSync(tempFile, output); // Atomic no-overwrite publication.
        } catch (error: unknown) {
          if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
            throw new Error(`Output file already exists: ${opts.output} (use --force to overwrite, or choose a different -o path)`);
          }
          throw error;
        }
      }
    } finally {
      if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
      fs.rmdirSync(tempDir);
    }
  } else if (!opts.verifyOnly && opts.output && typeof opts.output !== 'string') {
    const output = opts.output;
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      output.once('error', onError);
      try {
        output.write(res.buffer, (error?: Error | null) => {
          if (error) reject(error); // Keep the listener for the stream's error event.
          else { output.removeListener('error', onError); resolve(); }
        });
      } catch (error) {
        output.removeListener('error', onError);
        reject(error);
      }
    });
  }
  return {
    buffer: !opts.verifyOnly && opts.output === undefined ? res.buffer : undefined,
    metadata: res.metadata,
    integrityVerified: res.integrityVerified,
    bytesRestored: res.buffer.length,
    chunksRead: 0,
  };
}

// ─────────────────────────────────────────────────────────────
// peekStreamMetadata (sync, from a Buffer)
// ─────────────────────────────────────────────────────────────

/**
 * Peek a v4 archive's metadata WITHOUT decrypting the metadata payload (no
 * passphrase). Public fields that live in the clear trailer (version,
 * originalSize, chunkCount, chunkSize) are surfaced; sensitive fields
 * (originalName, checksum, strategy) are redacted — exactly like
 * `peekMetadata()` does for encrypted v3 packages.
 *
 * If `passphrase` is supplied, the encrypted metadata is decrypted and the full
 * metadata is returned.
 */
export async function peekStreamMetadata(craftBuffer: Buffer, passphrase?: string): Promise<StreamMetadata> {
  const { version } = readMagicVersion(craftBuffer);
  if (version !== STREAM_VERSION) {
    throw new Error(`peekStreamMetadata: not a v4 (streaming) package (version=${version}).`);
  }
  const view = craftBuffer;
  let offset = 7; // magic(6) + version(1)
  const rawMl = view.readUInt32BE(offset); offset += 4;
  const metaSectionLength = rawMl & METADATA_LENGTH_MASK;
  const isEncrypted = (rawMl & METADATA_ENCRYPTED_FLAG) !== 0;

  // Clear trailer (after the metadata section):
  //   DATA_SALT(16) | CHUNK_COUNT(4) | CHUNK_SIZE(4) | ORIGINAL_SIZE(8)
  const trailerOff = offset + metaSectionLength;
  if (trailerOff + SALT_LENGTH + 4 + 4 + 8 > view.length) {
    throw new Error('Invalid CRAFT v4 package: truncated chunk table.');
  }
  const chunkCount = view.readUInt32BE(trailerOff + SALT_LENGTH);
  const chunkSize = view.readUInt32BE(trailerOff + SALT_LENGTH + 4);
  const originalSize = readBigSize(view, trailerOff + SALT_LENGTH + 8);

  if (!isEncrypted || !passphrase) {
    return {
      version: STREAM_VERSION,
      streamingVersion: STREAM_VERSION,
      originalName: '[encrypted]',
      originalMime: '[encrypted]',
      originalSize,
      compressedSize: 0,
      compressionMode: 'stream',
      compressionStrategyName: '[encrypted]',
      encryptionAlgo: 'aes-256-gcm',
      originalChecksum: '[encrypted]',
      chunkSize,
      chunkCount,
      metadataEncrypted: true,
      createdAt: '[encrypted]',
    };
  }

  // Decrypt path
  if (offset + CRYPTO_OVERHEAD > view.length) throw new Error('Invalid CRAFT v4 package: truncated metadata.');
  const metaSalt = view.subarray(offset, offset + SALT_LENGTH); offset += SALT_LENGTH;
  const metaIv = view.subarray(offset, offset + IV_LENGTH); offset += IV_LENGTH;
  const metaAuthTag = view.subarray(offset, offset + AUTH_TAG_LENGTH); offset += AUTH_TAG_LENGTH;
  const encMetaLen = metaSectionLength - CRYPTO_OVERHEAD;
  const encryptedMeta = view.subarray(offset, offset + encMetaLen); offset += encMetaLen;
  let decrypted: Buffer;
  try {
    decrypted = await decryptMetadataAsync(encryptedMeta, passphrase, metaSalt, metaIv, metaAuthTag);
  } catch {
    throw new Error('Metadata decryption failed — the passphrase is incorrect.');
  }
  const meta = JSON.parse(decrypted.toString('utf-8')) as ParsedMetadata;
  return {
    version: STREAM_VERSION,
    streamingVersion: STREAM_VERSION,
    originalName: meta.originalName ?? '[encrypted]',
    originalMime: meta.originalMime ?? '[encrypted]',
    originalSize: meta.originalSize,
    compressedSize: meta.compressedSize ?? 0,
    compressionMode: 'stream',
    compressionStrategyName: meta.compressionStrategyName ?? 'Unknown',
    compressionStrategyKey: (meta.compressionStrategyKey ?? 'zstd') as 'zstd' | 'brotli',
    encryptionAlgo: meta.encryptionAlgo ?? 'aes-256-gcm',
    originalChecksum: meta.originalChecksum ?? '[encrypted]',
    chunkSize: (meta.chunkSize as number) || 0,
    chunkCount: (meta.chunkCount as number) || 0,
    metadataEncrypted: true,
    createdAt: meta.createdAt ?? new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────
// macroStream (universal: v1–v3 delegate to macro(); v4 streaming)
// ─────────────────────────────────────────────────────────────

/**
 * Restore a CRAFT archive with constant memory (v4) and universal compatibility.
 *
 * For v1/v2/v3 archives it delegates to the gold-standard `macro()` (which loads
 * the whole package — the legacy path). For v4 archives it streams chunk-by-
 * chunk: per-chunk AES-256-GCM decrypt → independent-codec decompress → SHA-256,
 * writing to `opts.output` (file path or Writable) or collecting a buffer when
 * no output is given (small files / tests).
 *
 * `opts.verifyOnly` decodes + verifies SHA without writing output (used by
 * `nanoStream`'s self-verify and by `craft verify --deep` on v4 packages).
 */
export async function macroStream(
  input: string | Buffer | NodeJS.ReadableStream,
  passphrase: string,
  opts: MacroStreamOptions = {},
): Promise<MacroStreamResult> {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error('Passphrase must be at least 12 characters for secure decryption.');
  }

  // For pathname input, open once: the same descriptor supplies the identity,
  // version and all decoded bytes, even if the pathname changes meanwhile.
  if (typeof input === 'string') {
    const file = await fs.promises.open(input, 'r');
    try {
      const stat = await file.stat();
      const source = !opts.verifyOnly && typeof opts.output === 'string'
        ? { path: input, stat }
        : undefined;
      if (source) assertDistinctFiles(source, opts.output as string);
      const read = fileReader(file, stat.size);
      const head = await read(7);
      const { version } = readMagicVersion(head);
      if (isLegacy(version)) {
        // fileReader uses positioned reads, so readFile starts at offset zero.
        const full = await file.readFile();
        return await decodeSingleFile(full, passphrase, opts, source);
      }
      let first = true;
      const readFromStart: ByteReader = async (length) => {
        if (first) {
          first = false;
          if (length !== head.length) throw new Error('Invalid CRAFT package: unexpected header length.');
          return head;
        }
        return read(length);
      };
      return await decodeV4(readFromStart, passphrase, opts, null, source);
    } finally {
      await file.close();
    }
  }

  let source: SourceIdentity | undefined;
  let streamPath: string | Buffer | undefined;
  const checkStreamSource = !opts.verifyOnly && typeof opts.output === 'string' && input instanceof fs.ReadStream;
  if (checkStreamSource && input instanceof fs.ReadStream) {
    const fd = readStreamDescriptor(input);
    if (fd !== undefined) {
      source = { stat: fs.fstatSync(fd) };
      assertDistinctFiles(source, opts.output as string);
    } else if (typeof input.path === 'string' || Buffer.isBuffer(input.path)) {
      streamPath = input.path;
    }
  }

  // ── Buffer input: route by version directly ──────────────────
  if (Buffer.isBuffer(input)) {
    const { version } = readMagicVersion(input);
    if (isLegacy(version)) {
      return decodeSingleFile(input, passphrase, opts);
    }
    const { read } = bufferReader(input);
    return decodeV4(read, passphrase, opts, null);
  }

  // ── Readable input: read 7 bytes to route, then continue ───────
  const head = await readExact(input, 7);
  if (checkStreamSource && input instanceof fs.ReadStream) {
    const fd = readStreamDescriptor(input);
    if (fd === undefined) throw new Error('Cannot verify the input archive identity from its read stream.');
    source = { path: streamPath, stat: fs.fstatSync(fd) };
    assertDistinctFiles(source, opts.output as string);
  }
  const { version } = readMagicVersion(head);
  if (isLegacy(version)) {
    const rest = await drainToBuffer(input);
    const full = Buffer.concat([head, rest]);
    return decodeSingleFile(full, passphrase, opts, source);
  }
  // v4: prepend the 7 peeked bytes so the reader starts at offset 0.
  const stream = prependBytes(head, input);
  const read: ByteReader = async (n: number) => readExact(stream, n);
  return decodeV4(read, passphrase, opts, stream, source);
}

// ─────────────────────────────────────────────────────────────
// v4 decode
// ─────────────────────────────────────────────────────────────

async function decodeV4(
  read: ByteReader,
  passphrase: string,
  opts: MacroStreamOptions,
  backingStream: Readable | null,
  source?: SourceIdentity,
): Promise<MacroStreamResult> {
  let header: { metadata: ParsedMetadata; dataSalt: Buffer; chunkCount: number; chunkSize: number; originalSize: number };
  try {
    header = await parseV4Header(read, passphrase);
  } catch (e: unknown) {
    throw mapError(e);
  }
  const { metadata, dataSalt, chunkCount, chunkSize, originalSize } = header;
  const strategy: 'zstd' | 'brotli' = (metadata.compressionStrategyKey as 'zstd' | 'brotli') ?? 'zstd';

  const dataKey = await deriveDataKey(passphrase, dataSalt); // throws only internal

  // ── Output sink ──
  const verifyOnly = !!opts.verifyOnly;
  let writer: WriteStream | null = null;
  let restoreTmp = '';
  const collected: Buffer[] = [];
  const emit = async (chunkBytes: Buffer) => {
    if (verifyOnly) return;
    if (opts.output === undefined) {
      collected.push(chunkBytes);
      return;
    }
    if (typeof opts.output === 'string') {
      if (!writer) throw new Error('writer not initialised');
      if (!writer.write(chunkBytes)) await new Promise<void>((r) => writer!.once('drain', r));
      return;
    }
    const w = opts.output as NodeJS.WritableStream & { write: (b: Buffer) => boolean };
    if (!w.write(chunkBytes)) await new Promise<void>((r) => w.once('drain', r));
  };

  if (!verifyOnly && typeof opts.output === 'string') {
    if (fs.existsSync(opts.output) && !opts.force) {
      throw new Error(`Output file already exists: ${opts.output} (use --force to overwrite, or choose a different -o path)`);
    }
    restoreTmp = path.join(
      path.dirname(path.resolve(opts.output)) || os.tmpdir(),
      `.${path.basename(opts.output)}.crafttmp-restore-${process.pid}-${Date.now()}`,
    );
    writer = createWriteStream(restoreTmp, { highWaterMark: Math.max(chunkSize, 64 * 1024) });
  }

  try {
    const sha = createHash('sha256');
    let bytesRestored = 0;
    let chunksRead = 0;

    for (let i = 0; i < chunkCount; i++) {
      const compLen = (await read(4)).readUInt32BE(0);
      const iv = await read(IV_LENGTH);
      const authTag = await read(AUTH_TAG_LENGTH);
      const ct = await read(compLen);

      let compressed: Buffer;
      try {
        compressed = decryptChunkSync(ct, dataKey, iv, authTag);
      } catch {
        throw new Error(`Integrity failure: chunk #${i} AES-256-GCM authentication tag did not verify (wrong passphrase or data tampering).`);
      }

      let chunkBytes: Buffer;
      try {
        // Async chunk codec — decode runs on the libuv threadpool.
        chunkBytes = await decompressChunkAsync(compressed, strategy);
      } catch {
        throw new Error(`Integrity failure: chunk #${i} decompression failed (corrupt compressed payload).`);
      }

      // Guard against over-long archives that would overflow originalSize.
      if (bytesRestored + chunkBytes.length > originalSize) {
        chunkBytes = chunkBytes.subarray(0, Math.max(0, originalSize - bytesRestored));
      }

      await emit(chunkBytes);
      sha.update(chunkBytes.subarray(0, chunkBytes.length)); // full plaintext chunk
      bytesRestored += chunkBytes.length;
      chunksRead += 1;
    }

    if (backingStream) {
      // We drained exactly the bytes we needed via manual readExact() calls on a
      // paused stream; do not wait for 'end' (it only fires after a terminal
      // read() that returns null, which we never issue). Just release the handle.
      backingStream.destroy();
    }

    const digest = sha.digest('hex');
    const integrityVerified = digest === metadata.originalChecksum && bytesRestored === originalSize;
    if (!integrityVerified) {
      throw new Error(
        'INTEGRITY FAILURE: SHA-256 checksum mismatch! The restored data does not match the original. ' +
        'This could indicate data corruption or an incorrect passphrase.',
      );
    }

    // Atomically publish the restored file (if a path output was requested).
    if (writer) {
      writer.end();
      await finished(writer);
      assertDistinctFiles(source, opts.output as string);
      fs.renameSync(restoreTmp, opts.output as string); // clobbers only when --force pre-checks
    }

    const buffer = opts.output === undefined && !verifyOnly
      ? Buffer.concat(collected, bytesRestored)
      : undefined;
    return {
      buffer,
      metadata: metadata as unknown as StreamMetadata,
      integrityVerified,
      bytesRestored,
      chunksRead,
    };
  } finally {
    if (writer) { try { writer.destroy(); } catch { /* ignore */ } }
    if (restoreTmp) { try { if (fs.existsSync(restoreTmp)) fs.unlinkSync(restoreTmp); } catch { /* ignore */ } }
  }
}

async function parseV4Header(read: ByteReader, passphrase: string): Promise<{
  metadata: ParsedMetadata;
  dataSalt: Buffer;
  chunkCount: number;
  chunkSize: number;
  originalSize: number;
}> {
  // Consume the 7-byte magic+version (the stream/reader is always at offset 0;
  // this unifies the Buffer, file-path and Readable input paths).
  const head = await read(7);
  const { version } = readMagicVersion(head);
  if (version !== STREAM_VERSION) {
    throw new Error(`Invalid CRAFT package: stream decoder expected v4, found version ${version}.`);
  }
  const mlBuf = await read(4);
  const rawMl = mlBuf.readUInt32BE(0);
  const { isEncrypted, length: metaSectionLength } = resolveStreamMetaEncryption(4, rawMl);
  if (!isEncrypted) {
    throw new Error('Invalid CRAFT v4 package: metadata must be encrypted (encrypted-metadata flag expected).');
  }
  const encMetaLen = metaSectionLength - CRYPTO_OVERHEAD;
  if (encMetaLen <= 0) throw new Error('Invalid CRAFT v4 package: encrypted metadata is empty.');
  const metaSalt = await read(SALT_LENGTH);
  const metaIv = await read(IV_LENGTH);
  const metaAuthTag = await read(AUTH_TAG_LENGTH);
  const encryptedMeta = await read(encMetaLen);
  let decrypted: Buffer;
  try {
    decrypted = await decryptMetadataAsync(encryptedMeta, passphrase, metaSalt, metaIv, metaAuthTag);
  } catch (e: unknown) {
    throw new Error(`Metadata decryption failed — the passphrase is incorrect. (${e instanceof Error ? e.message : String(e)})`);
  }
  const metadata = JSON.parse(decrypted.toString('utf-8')) as ParsedMetadata;
  const dataSalt = await read(SALT_LENGTH);
  const chunkCount = (await read(4)).readUInt32BE(0);
  const chunkSize = (await read(4)).readUInt32BE(0);
  const originalSize = readBigSize(await read(8), 0);
  return { metadata, dataSalt, chunkCount, chunkSize, originalSize };
}

async function drainToBuffer(readable: NodeJS.ReadableStream): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of readable as AsyncIterable<Buffer | string>) {
    const piece: Buffer = Buffer.isBuffer(part) ? part : Buffer.from(part);
    parts.push(piece);
  }
  return Buffer.concat(parts);
}

function mapError(e: unknown): Error {
  if (e instanceof Error && (e.message.includes('auth tag') || e.message.includes('Unsupported state') || e.message.includes('EVP_DecryptFinal'))) {
    return new Error('Metadata decryption failed — the passphrase is incorrect.');
  }
  return e instanceof Error ? e : new Error(String(e));
}
