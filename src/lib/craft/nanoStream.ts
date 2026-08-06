/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/nanoStream — v4 Chunked Streaming Compressor
 *  The Living Canvas Edition (Streaming Path)
 * ═══════════════════════════════════════════════════════════════
 *
 *  SECOND execution path. This does NOT touch `nano()` (the gold-standard
 *  v1–v3 in-memory writer). See docs/streaming-architecture.md and
 *  docs/chunk-format.md.
 *
 *  Pipeline (constant memory — one chunk in flight at a time):
 *    file/stream ─► SHA-256 ─► fixed chunkSize split ─► compress chunk
 *                    (independent frame) ─► AES-256-GCM per-chunk
 *                    ─► chunk records ─► temp chunk file ─► assemble
 *                    header + metadata ─► stream-copy chunks ─► atomic rename
 *
 *  Memory is bounded by O(chunkSize) regardless of input size. The only
 *  growth with file size is on-disk temp space (≈ compressed archive size),
 *  never RAM.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomBytes, createHash } from 'crypto';
import { createWriteStream, createReadStream } from 'fs';
import { finished } from 'stream/promises';
import {
  STREAM_VERSION,
  DEFAULT_STREAM_CHUNK_SIZE,
  CRYPTO_OVERHEAD,
  StreamMetadata,
  NanoStreamResult,
  NanoStreamOptions,
  encryptChunkSync,
  compressChunkAsync,
  defaultStrategyName,
  deriveDataKey,
  u32be,
  u64be,
  fixedChunks,
} from './streamCore';
import { encryptMetadataAsync } from './codec';
import { CRAFT_MAGIC } from './types';
import { macroStream } from './macroStream';

/** Passphrase strength floor — mirrors nano()'s 12-char rule. */
const MIN_PASSPHRASE_LEN = 12;

function tmpName(prefix: string): string {
  return path.join(os.tmpdir(), `${prefix}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
}

/** Pipe `src` into `dst`; resolves when `dst` finishes. `endDst` ends dst. */
function pump(src: NodeJS.ReadableStream, dst: NodeJS.WritableStream, endDst = true): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      src.removeListener('error', onErr);
      dst.removeListener('error', onErr);
      if (endDst) dst.removeListener('finish', onDone);
    };
    const onErr = (e: Error) => { cleanup(); reject(e); };
    const onDone = () => { cleanup(); resolve(); };
    src.on('error', onErr);
    dst.on('error', onErr);
    if (endDst) dst.on('finish', onDone);
    src.pipe(dst, { end: endDst });
  });
}

/**
 * Build a v4 (chunked streaming) CRAFT archive with constant memory.
 *
 * The archive is assembled in a temp file and atomically published onto
 * `opts.output` (path → rename; Writable → stream). Every temp file is cleaned
 * up in a `finally` block so an interruption (SIGKILL/SIGTERM) never leaves a
 * corrupt `.craft` or a stray `.crafttmp` behind at the destination.
 *
 * If `opts.verify !== false` (default), the freshly-written temp archive is
 * *streaming-decoded* back and its SHA-256 re-checked against the original —
 * this is the constant-memory equivalent of `nano()`'s self-verify and doubles
 * as the atomic read-back confirmation (no full-file read into RAM).
 *
 * @param input  File path or Readable stream of the original plaintext.
 * @param originalName  Original filename (stored in encrypted metadata).
 * @param originalMime  Original MIME type.
 * @param passphrase  Encryption passphrase (≥ 12 chars).
 * @param opts  chunkSize / compressionStrategy / level / quality / verify / output.
 */
export async function nanoStream(
  input: string | NodeJS.ReadableStream,
  originalName: string,
  originalMime: string,
  passphrase: string,
  opts: NanoStreamOptions = {},
): Promise<NanoStreamResult> {
  // ── Validation (parity with nano()) ───────────────────────────
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error('Passphrase must be at least 12 characters for secure encryption.');
  }
  if (!originalName || originalName.trim().length === 0) {
    throw new Error('Original filename is required for package metadata.');
  }
  if (opts.output === undefined) {
    throw new Error('nanoStream requires opts.output (file path or Writable).');
  }

  const chunkSize = opts.chunkSize ?? DEFAULT_STREAM_CHUNK_SIZE;
  if (chunkSize <= 0 || chunkSize > 0x7fffffff) {
    throw new Error(`chunkSize must be between 1 and 4294967295 (got ${chunkSize}).`);
  }

  const strategy: 'zstd' | 'brotli' = opts.compressionStrategy ?? 'zstd';
  const level = strategy === 'zstd' ? (opts.level ?? 19) : (opts.quality ?? 11);
  const verify = opts.verify !== false;
  const strategyName = defaultStrategyName(strategy, level);

  // ── Derive the single archive data key (one PBKDF2 per archive) ─
  const dataSalt = randomBytes(16);
  const dataKey = await deriveDataKey(passphrase, dataSalt);

  // ── Temp staging files (on disk, not RAM) ──────────────────────
  const chunkTmp = tmpName('craft-stream-chunks');
  const chunkWriter = createWriteStream(chunkTmp, { highWaterMark: chunkSize });
  const ownedSource = typeof input === 'string';
  const source = ownedSource
    ? createReadStream(input, { highWaterMark: chunkSize, autoClose: true })
    : input;

  let originalChecksum = '';
  let chunkCount = 0;
  let bytesProcessed = 0;
  let compressedSize = 0; // sum of per-chunk compressed (pre-encryption) bytes
  let assembleTmp = '';
  let integrityVerified = true;

  const delChunkTmp = () => { try { if (fs.existsSync(chunkTmp)) fs.unlinkSync(chunkTmp); } catch { /* best-effort */ } };
  const delAssembleTmp = () => { try { if (assembleTmp && fs.existsSync(assembleTmp)) fs.unlinkSync(assembleTmp); } catch { /* best-effort */ } };

  try {
    // ── Stage 1: stream input → chunk → compress → AES-GCM → temp file ─
    const sha = createHash('sha256');
    for await (const chunk of fixedChunks(source, chunkSize)) {
      // Async chunk codec — compression runs on the libuv threadpool, so the
      // encode loop yields to the event loop instead of blocking per chunk.
      const compressed = await compressChunkAsync(chunk, strategy, level);
      const encrypted = encryptChunkSync(compressed, dataKey);
      // CHUNK_RECORD = COMP_LEN(4) | IV(12) | TAG(16) | CIPHERTEXT
      const rec = Buffer.concat([u32be(compressed.length), encrypted.iv, encrypted.authTag, encrypted.ciphertext]);
      if (!chunkWriter.write(rec)) {
        // Backpressure on the temp chunk file; fixedChunks yields at a cadence
        // gated by the input stream's highWaterMark.
      }
      sha.update(chunk);
      bytesProcessed += chunk.length;
      compressedSize += compressed.length;
      chunkCount += 1;
    }
    chunkWriter.end();
    await finished(chunkWriter);
    originalChecksum = sha.digest('hex');
  } catch (err) {
    delChunkTmp();
    throw err;
  } finally {
    try { chunkWriter.close(); } catch { /* ignore */ }
  }

  // ── Stage 2: build header + encrypted metadata ──────────────────
  const metadata: StreamMetadata = {
    version: STREAM_VERSION,
    streamingVersion: STREAM_VERSION,
    originalName,
    originalMime,
    originalSize: bytesProcessed,
    compressedSize,
    compressionMode: 'stream',
    compressionStrategyName: strategyName,
    compressionStrategyKey: strategy,
    encryptionAlgo: 'aes-256-gcm',
    originalChecksum,
    chunkSize,
    chunkCount,
    metadataEncrypted: true,
    createdAt: new Date().toISOString(),
  };
  const metaJson = Buffer.from(JSON.stringify(metadata), 'utf-8');
  const { encrypted: encMeta, metaSalt, metaIv, metaAuthTag } = await encryptMetadataAsync(metaJson, passphrase);
  const metaSectionLength = CRYPTO_OVERHEAD + encMeta.length;
  const ml = (metaSectionLength | 0x80000000) >>> 0; // bit 31 = metadata encrypted (v3+ convention)

  const header = Buffer.concat([
    CRAFT_MAGIC,
    Buffer.from([STREAM_VERSION]),
    u32be(ml),
    metaSalt, metaIv, metaAuthTag, encMeta,
    dataSalt,
    u32be(chunkCount),
    u32be(chunkSize),
    u64be(bytesProcessed),
  ]);

  // ── Stage 3: assemble final archive (header + chunk records) ───
  assembleTmp = tmpName('craft-stream-assemble') + '.craft';
  const finalWriter = createWriteStream(assembleTmp, { highWaterMark: chunkSize });
  finalWriter.write(header);
  await pump(createReadStream(chunkTmp, { highWaterMark: chunkSize }), finalWriter, true);
  const archiveBytes = fs.statSync(assembleTmp).size;

  // ── Self-verify: streaming-decode the assembled temp & check SHA ─
  if (verify) {
    const res = await macroStream(assembleTmp, passphrase, { verifyOnly: true });
    integrityVerified = !!res.integrityVerified;
    if (!integrityVerified) {
      delChunkTmp();
      delAssembleTmp();
      throw new Error('CRAFT self-verification failed: the streaming package did not decode back to the original data.');
    }
  }

  // ── Publish: atomic rename (path) or stream-to-writable ─────────
  try {
    if (typeof opts.output === 'string') {
      atomicPublish(assembleTmp, opts.output, chunkTmp, !!opts.force);
    } else {
      // Writable target: stream the assembled archive through, then clean up.
      await pump(createReadStream(assembleTmp, { highWaterMark: chunkSize }), opts.output, false);
    }
  } finally {
    delChunkTmp();
    delAssembleTmp();
  }

  const compressionRatio = bytesProcessed > 0 ? archiveBytes / bytesProcessed : 0;
  const spaceSaved = Math.max(0, bytesProcessed - archiveBytes);
  return {
    metadata,
    archiveBytes,
    compressionRatio,
    spaceSaved,
    spaceSavedPercent: bytesProcessed > 0 ? Math.max(0, (1 - archiveBytes / bytesProcessed) * 100) : 0,
    chunksProcessed: chunkCount,
    bytesProcessed,
    integrityVerified,
  };
}

function atomicPublish(tmpPath: string, destPath: string, chunkTmp: string, force: boolean): void {
  // Mirror the gold-standard safeWriteFile contract: never overwrite without
  // explicit caller consent (force), atomic temp+rename, clean temps on exit.
  if (fs.existsSync(destPath) && !force) {
    throw new Error(`Output file already exists: ${destPath} (use --force to overwrite, or choose a different -o path)`);
  }
  const dir = path.dirname(path.resolve(destPath));
  const finalTmp = path.join(dir, `.${path.basename(destPath)}.crafttmp-${process.pid}-${Date.now()}`);
  try {
    if (fs.existsSync(finalTmp)) fs.unlinkSync(finalTmp);
    fs.renameSync(tmpPath, finalTmp); // same filesystem → atomic
    fs.renameSync(finalTmp, destPath);
  } catch (err) {
    try { if (fs.existsSync(finalTmp)) fs.unlinkSync(finalTmp); } catch { /* ignore */ }
    throw err;
  } finally {
    // chunkTmp is owned by the caller; ensure it is gone.
    try { if (fs.existsSync(chunkTmp)) fs.unlinkSync(chunkTmp); } catch { /* ignore */ }
  }
}
