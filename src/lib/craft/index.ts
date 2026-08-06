/**
 * ═══════════════════════════════════════════════════════════════
 *  CRAFT — Nano/Macro Encryption & Compression Engine
 *  Package Index — The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  7-Fold Encryption Tool:
 *    1. Brotli Compression — maximum quality (Q11)
 *    2. Delta Encoding — sequential data optimization
 *    3. Move-to-Front — recurring symbol optimization
 *    4. Run-Length Encoding — repeated byte collapse
 *    5. Byte-Pair Encoding — frequent pair replacement
 *    6. AES-256-GCM Encryption — authenticated encryption
 *    7. SHA-256 Integrity — lossless verification
 */

// Primary Operations
export { nano } from './nano';
export { macro, peekMetadata } from './macro';

// Streaming path (v4 — constant-memory, second execution path).
// See docs/streaming-architecture.md and docs/chunk-format.md.
export { nanoStream } from './nanoStream';
export { macroStream, peekStreamMetadata } from './macroStream';
export type {
  StreamMetadata,
  NanoStreamResult,
  MacroStreamResult,
  NanoStreamOptions,
  MacroStreamOptions,
  StreamCodecOptions,
  StreamCompressionStrategy,
  ChunkCipherBag,
} from './streamCore';

// Hardening: environment/pipeline sanity check
export { selfTest } from './self-test';
export type { SelfTestResult } from './self-test';

// Hardening: passive bitrot/corruption detection for archived packages
export {
  computeFixityRecord,
  verifyFixityRecord,
  serializeFixityRecord,
  parseFixityRecord,
  fixitySidecarPath,
} from './fixity';
export type { FixityRecord, FixityCheckResult } from './fixity';

// 7-Fold Compression Engine
// compress7Async/decompress7Async run the Brotli/Zstd passes on the libuv
// threadpool; the sync variants are retained for legacy/sync callers.
export { compress7, decompress7, compress7Async, decompress7Async } from './compress7';
export type { Compress7Result, CompressionStrategy } from './compress7';

// Codec Layer
export { compress, decompress, encrypt, decrypt, deriveKey } from './codec';
export type { EncryptResult } from './codec';

// Integrity Layer
export { checksum, verify } from './integrity';

// Types
export type {
  CraftMetadata,
  NanoResult,
  MacroResult,
  NanoOptions,
  CompressionMode,
} from './types';
export {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  PBKDF2_ITERATIONS,
  AES_KEY_LENGTH,
} from './types';
