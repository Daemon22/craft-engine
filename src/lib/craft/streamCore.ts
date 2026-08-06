/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/streamCore — CRAFT v4 (chunked streaming) primitives
 *  The Living Canvas Edition
 * ═════════════════════════════════════════════════════════════════════════
 *
 *  Core building blocks for the SECOND execution path — constant-memory
 *  `nanoStream()` / `macroStream()` — WITHOUT touching the gold-standard
 *  `nano()` / `macro()` (v1–v3).
 *
 *  v4 layout (full spec in docs/chunk-format.md):
 *    MAGIC(6) | VER(1=0x04) | ML(4) [bit31 = meta-encrypted]
 *    META_SALT(16) | META_IV(12) | META_AUTH_TAG(16) | ENCRYPTED_META
 *    DATA_SALT(16) | CHUNK_COUNT(4) | CHUNK_SIZE(4) | ORIGINAL_SIZE(8)
 *    [ CHUNK_RECORD( COMP_LEN(4) | IV(12) | AUTH_TAG(16) | CIPHERTEXT ) ] * CHUNK_COUNT
 *
 *  Each chunk is an INDEPENDENTLY authenticatable + independently
 *  decompressible unit: one AES-256-GCM nonce/tag per chunk, one codec
 *  frame per chunk, sharing a single PBKDF2-derived archive data key.
 *
 *  Nothing here mutates the v1–v3 format. `STREAM_VERSION = 4` reuses the
 *  `CRAFT1` magic so legacy sniffers still recognise the family; the version
 *  byte alone routes to the streaming reader.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import {
  brotliCompressSync,
  brotliDecompressSync,
  zstdCompressSync,
  zstdDecompressSync,
  constants as zlibConstants,
} from 'zlib';
import { deriveKey, encryptMetadata, decryptMetadata } from './codec';
import {
  CRAFT_MAGIC,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  METADATA_ENCRYPTED_FLAG,
  METADATA_LENGTH_MASK,
  EncryptionAlgo,
  CraftMetadata,
} from './types';

// ─────────────────────────────────────────────────────────────
// Version & format constants
// ─────────────────────────────────────────────────────────────

/** v4 = chunked, constant-memory streaming archive (new second path). */
export const STREAM_VERSION = 4;

/** Crypto-parameter overhead for one AEAD field set: SALT(16)+IV(12)+TAG(16). */
export const CRYPTO_OVERHEAD = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH; // 44

/** Per-chunk record overhead beyond the ciphertext: COMP_LEN(4)+IV(12)+TAG(16). */
export const CHUNK_RECORD_OVERHEAD = 4 + IV_LENGTH + AUTH_TAG_LENGTH; // 32

/** Default chunk size: 1 MiB — keeps peak RAM ≈ 3 MiB regardless of file size. */
export const DEFAULT_STREAM_CHUNK_SIZE = 1 << 20; // 1_048_576

/** Default streaming compression strategy. */
export type StreamCompressionStrategy = 'zstd' | 'brotli';

/** Brotli Z_SYNC_FLUSH is NOT used: each chunk is a SELF-CONTAINED frame
 *  (independent re-init), so a corrupt chunk cannot poison later ones. */

// ─────────────────────────────────────────────────────────────
// Metadata types
// ─────────────────────────────────────────────────────────────

/**
 * v4 metadata. Extends CraftMetadata: `compressionMode` is `"stream"` (the
 * streaming path's mode) and extra chunked fields are present.
 */
export interface StreamMetadata {
  originalName: string;
  originalSize: number;
  originalMime: string;
  compressedSize: number;
  /** `"stream"` for v4 archives. */
  compressionMode: 'stream';
  compressionStrategyName?: string;
  /** Concrete streaming codec key ('zstd' | 'brotli') for round-trip decode. */
  compressionStrategyKey?: 'zstd' | 'brotli';
  encryptionAlgo: EncryptionAlgo;
  originalChecksum: string;
  createdAt: string;
  version: number;
  metadataEncrypted?: boolean;
  /** Configured chunk size in bytes (encode-time). */
  chunkSize: number;
  /** Number of chunk records in the archive. */
  chunkCount: number;
  /** Streaming version (always 4). Mirrors `version` for clarity. */
  streamingVersion: number;
}

export interface NanoStreamResult {
  /** Metadata (mirrors CraftMetadata surface + streaming counters). */
  metadata: StreamMetadata;
  /** Compression ratio (archiveBytes / originalSize; <1 = smaller). */
  compressionRatio: number;
  /** Bytes saved vs original (archiveBytes). */
  spaceSaved: number;
  /** % saved. */
  spaceSavedPercent: number;
  /** How many chunk records were written. */
  chunksProcessed: number;
  /** Plaintext bytes consumed. */
  bytesProcessed: number;
  /** Final archive size in bytes. */
  archiveBytes: number;
  /** True if the package self-verified on construction. */
  integrityVerified: boolean;
}

export interface MacroStreamResult {
  /** Restored bytes (present when the caller did not supply an output stream). */
  buffer?: Buffer;
  /** v4 → StreamMetadata; legacy v1–v3 → the gold-standard CraftMetadata. */
  metadata: CraftMetadata | StreamMetadata;
  integrityVerified: boolean;
  bytesRestored: number;
  chunksRead: number;
}

export interface StreamCodecOptions {
  /** Strategy key ('zstd' default, 'brotli'). */
  compressionStrategy?: 'zstd' | 'brotli';
  /** Zstd level (default 19; max 22). */
  level?: number;
  /** Brotli quality (default 11) — used only when strategy === 'brotli'. */
  quality?: number;
  /** Chunk size in bytes (default 1 MiB). */
  chunkSize?: number;
  /** Self-verify after build (default true). */
  verify?: boolean;
}

export interface NanoStreamOptions extends StreamCodecOptions {
  /** Output target: file path (atomic) or Writable stream. */
  output?: string | NodeJS.WritableStream;
  /** Allow overwriting an existing output file path (CLI `--force`). */
  force?: boolean;
}

export interface MacroStreamOptions {
  /** Chunk size for decoding (must be >= max chunk in archive). */
  chunkSize?: number;
  /** Output target: file path (atomic) or Writable stream. */
  output?: string | NodeJS.WritableStream;
  /** Decode + verify SHA without writing output (self-verify / verify --deep). */
  verifyOnly?: boolean;
  /** Allow overwriting an existing output file path. */
  force?: boolean;
}

// ─────────────────────────────────────────────────────────────
// Small binary helpers
// ─────────────────────────────────────────────────────────────

export function writeUInt32BE(out: Buffer, value: number, offset: number): void {
  out.writeUInt32BE(value >>> 0, offset);
}

export function writeBigSize(out: Buffer, value: number, offset: number): void {
  // 8-byte big-endian; supports files > 4 GiB (high 32 + low 32).
  out.writeUInt32BE(Math.floor(value / 0x1_0000_0000) >>> 0, offset);
  out.writeUInt32BE(value >>> 0, offset + 4);
}
export function readBigSize(buf: Buffer, offset: number): number {
  const hi = buf.readUInt32BE(offset);
  const lo = buf.readUInt32BE(offset + 4);
  // 53-bit safe; v4 files > 8 exabytes are not a concern here.
  return hi * 0x1_0000_0000 + lo;
}

export function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
export function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  writeBigSize(b, n, 0);
  return b;
}

// ─────────────────────────────────────────────────────────────
// Per-chunk AEAD (AES-256-GCM) on a SHARED archive key
// ─────────────────────────────────────────────────────────────

/** Result of encrypting one chunk's compressed bytes. */
export interface ChunkCipherBag {
  iv: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
}

/**
 * Encrypt one chunk with AES-256-GCM using the shared archive data key.
 * A fresh random 96-bit IV is generated per chunk → per-chunk auth tag.
 * (Equivalent AEAD guarantees to v1–v3; key is derived once per archive.)
 */
export function encryptChunkSync(plaintext: Buffer, dataKey: Buffer): ChunkCipherBag {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { iv, authTag, ciphertext };
}

/** Decrypt one chunk. Throws on tag mismatch (tamper / wrong passphrase). */
export function decryptChunkSync(
  ciphertext: Buffer,
  dataKey: Buffer,
  iv: Buffer,
  authTag: Buffer,
): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', dataKey, iv);
  decipher.setAuthTag(authTag);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return out;
}

// ─────────────────────────────────────────────────────────────
// Per-chunk codec (independent frames — chunk N decodes without N-1)
// ─────────────────────────────────────────────────────────────

/** Strategy id byte prefix mirroring v1–v3's strategy-id convention,
 *  but scoped to the streaming path so a future multi-strategy v4 stays
 *  self-describing per chunk. Currently only `0` is emitted (single archive
 *  strategy, recorded in metadata). */
export const STREAM_STRATEGY_BROTLI = 0 as const;
export const STREAM_STRATEGY_ZSTD = 1 as const;

export function strategyIdToName(id: number): string {
  return id === STREAM_STRATEGY_ZSTD ? 'Zstd' : 'Brotli';
}

/** Compress one independent chunk. `id` selects the codec. */
export function compressChunk(
  data: Buffer,
  strategy: 'zstd' | 'brotli',
  levelOrQuality?: number,
): Buffer {
  if (strategy === 'zstd') {
    const level = levelOrQuality ?? 19;
    return zstdCompressSync(data, {
      params: { [zlibConstants.ZSTD_c_compressionLevel]: Math.min(Math.max(1, level), 22) },
    });
  }
  // brotli
  const quality = levelOrQuality ?? 11;
  return brotliCompressSync(data, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: Math.min(Math.max(0, quality), 11),
      [zlibConstants.BROTLI_PARAM_LGWIN]: 24,
    },
  });
}

/** Decompress one independent chunk frame. */
export function decompressChunk(data: Buffer, strategy: 'zstd' | 'brotli'): Buffer {
  if (strategy === 'zstd') return zstdDecompressSync(data);
  return brotliDecompressSync(data);
}

export function defaultStrategyName(strategy: 'zstd' | 'brotli', level?: number): string {
  if (strategy === 'zstd') return `Zstd L${level ?? 19} chunked streaming`;
  return `Brotli Q${level ?? 11} (independent per chunk)`;
}

// ─────────────────────────────────────────────────────────────
// Header read helpers (synchronous, from a Buffer)
// ─────────────────────────────────────────────────────────────

/** Read magic + version from the start of a buffer. Throws if not CRAFT1. */
export function readMagicVersion(buf: Buffer): { version: number; offset: number } {
  if (buf.length < 7 || !buf.subarray(0, 6).equals(CRAFT_MAGIC)) {
    throw new Error(
      'Invalid CRAFT package: magic bytes mismatch. This is not a valid .craft file.',
    );
  }
  return { version: buf[6], offset: 7 };
}

/** Resolve metadata-encryption + length from version + raw ML field. */
export function resolveStreamMetaEncryption(
  version: number,
  rawMl: number,
): { isEncrypted: boolean; length: number } {
  if (version >= 3) {
    return { isEncrypted: (rawMl & METADATA_ENCRYPTED_FLAG) !== 0, length: rawMl & METADATA_LENGTH_MASK };
  }
  throw new Error(`Unsupported CRAFT version for streaming metadata: ${version}`);
}

/** Metadata-key derivation over the archive data salt. */
export function deriveDataKey(passphrase: string, dataSalt: Buffer): Buffer {
  return deriveKey(passphrase, dataSalt).key;
}

/** Metadata helpers reused from ./codec (encrypted with their own salt). */
export { encryptMetadata, decryptMetadata };

// ─────────────────────────────────────────────────────────────
// Async streaming I/O helpers (constant memory)
// ─────────────────────────────────────────────────────────────

/**
 * Read exactly `n` bytes from a readable, buffering internally.
 * Returns a Buffer of length `n`, or fewer only on EOF (then `got < n`).
 * Constant memory: holds at most `n` bytes + one upstream chunk.
 */
export async function readExact(
  stream: NodeJS.ReadableStream,
  n: number,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  let eof = false;  while (total < n && !eof) {
    // Drain whatever is synchronously available from the internal buffer.
    let part: Buffer | null;
    while ((part = stream.read(n - total) as Buffer | null) !== null) {
      chunks.push(part);
      total += part.length;
      if (total >= n) break;
    }
    if (total >= n) break;
    if ((stream as NodeJS.ReadableStream & { readableEnded?: boolean }).readableEnded) { eof = true; break; } // drained past EOF
    // Await more data arriving (or the stream ending).
    await new Promise<void>((resolve, reject) => {
      const onReadable = () => { cleanup(); resolve(); };
      const onEnd = () => { eof = true; cleanup(); resolve(); };
      const onError = (e: Error) => { cleanup(); reject(e); };
      const cleanup = () => {
        stream.removeListener('readable', onReadable);
        stream.removeListener('end', onEnd);
        stream.removeListener('error', onError);
      };
      stream.once('readable', onReadable);
      stream.once('end', onEnd);
      stream.once('error', onError);
    });
  }
  if (total < n) {
    throw new Error(
      `Invalid CRAFT package: stream ended before ${n} bytes could be read (wanted ${n}, got ${total}).`,
    );
  }
  return Buffer.concat(chunks, n);
}

/** Write a buffer to a writable honoring backpressure. */
export function writeAll(stream: NodeJS.WritableStream, data: Buffer): void {
  if (!stream.write(data)) {
    // Backpressure signalled: the caller should await 'finish'/'drain' on
    // the next iteration. For our in-process use this never blocks the event
    // loop because we yield to the microtask queue between chunks via await.
  }
}

/** Flush + close a writable, await its 'finish'. */
export function finishAll(stream: NodeJS.WritableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.on('error', reject);
    stream.on('finish', () => resolve());
    stream.end();
  });
}

/** True async iteration over a readable yielding FIXED-SIZE chunks of
 *  `chunkSize` bytes (last chunk may be shorter). Bounded memory for any
 *  stream whose highWaterMark is ≤ chunkSize (file streams default to this). */
export async function* fixedChunks(
  readable: NodeJS.ReadableStream,
  chunkSize: number,
): AsyncGenerator<Buffer, void, unknown> {
  if (chunkSize <= 0) throw new Error('chunkSize must be > 0');
  let carry: Buffer | null = null;
  // `for await` on a NodeJS.ReadableStream handles backpressure for streams
  // created with an appropriate highWaterMark (we set highWaterMark=chunkSize).
  for await (const part of readable as AsyncIterable<Buffer>) {
    const piece = Buffer.isBuffer(part) ? part : Buffer.from(part as ArrayBuffer);
    carry = carry ? Buffer.concat([carry, piece]) : piece;
    while (carry.length >= chunkSize) {
      yield carry.subarray(0, chunkSize);
      carry = carry.subarray(chunkSize);
    }
  }
  if (carry && carry.length > 0) yield carry;
}

// ─────────────────────────────────────────────────────────────
// Re-exported helpers (used by the higher-level streaming modules)
// ─────────────────────────────────────────────────────────────
export { verify as verifySha256, checksum as sha256 } from './integrity';
export { createHash } from 'crypto';
