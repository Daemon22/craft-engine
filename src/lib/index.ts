/**
 * CRAFT — Nano/Macro Encryption & Compression Engine
 *
 * 7-Fold Encryption Pipeline:
 *   1. Brotli Compression (Q11)
 *   2. Delta Encoding
 *   3. Move-to-Front
 *   4. Run-Length Encoding
 *   5. Byte-Pair Encoding
 *   6. AES-256-GCM Encryption
 *   7. SHA-256 Integrity
 */

// Primary Operations
export { nano } from './nano.js';
export { macro, peekMetadata } from './macro.js';

// 7-Fold Compression Engine
export { compress7, decompress7 } from './compress7.js';
export type { Compress7Result, CompressionStrategy } from './compress7.js';

// Codec Layer
export { compress, decompress, encrypt, encryptAsync, decrypt, decryptAsync, deriveKey, deriveKeyAsync } from './codec.js';
export type { EncryptResult } from './codec.js';

// Integrity Layer
export { checksum, verify } from './integrity.js';

// Archive (multi-file) support
export { archive, extract, peekArchiveMetadata } from './archive.js';
export type { ArchiveEntry, ArchiveResult, ExtractResult } from './archive.js';

// Streaming support
export { nanoStream, macroStream } from './stream.js';
export type { StreamOptions, StreamResult } from './stream.js';

// Compression Analytics
export { CompressionAnalytics, globalAnalytics } from './analytics.js';
export type { CompressionObservation, StrategyStats, AnalyticsReport } from './analytics.js';

// Types
export type {
  CraftMetadata,
  NanoResult,
  MacroResult,
  NanoOptions,
  CompressionMode,
} from './types.js';
export {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  CRAFT_ARCHIVE_VERSION,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  PBKDF2_ITERATIONS,
  AES_KEY_LENGTH,
} from './types.js';
