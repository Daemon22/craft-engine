/**
 * CRAFT — Type Definitions & Constants
 *
 * Package format (v2):
 *   MAGIC(6) | VER(1) | ML(4) | META(JSON) | SALT(16) | IV(12) | AUTHTAG(16) | ENCRYPTED(var)
 *
 * The ENCRYPTED payload contains: [strategy_id(1), ...compressed_data]
 * where compressed_data = Brotli(pre_processed(original_data))
 */

/** Magic bytes identifying a CRAFT package — "CRAFT1" */
export const CRAFT_MAGIC = Buffer.from('CRAFT1');

/** Current CRAFT format version (v2 = 7-fold compression) */
export const CRAFT_VERSION = 2;

/** CRAFT archive format version (v3 = multi-file) */
export const CRAFT_ARCHIVE_VERSION = 3;

/** Salt length for PBKDF2 key derivation (16 bytes) */
export const SALT_LENGTH = 16;

/** IV length for AES-256-GCM (12 bytes) */
export const IV_LENGTH = 12;

/** Auth tag length for AES-256-GCM (16 bytes = 128-bit tag) */
export const AUTH_TAG_LENGTH = 16;

/** PBKDF2 iterations (600,000 for strong brute-force resistance) */
export const PBKDF2_ITERATIONS = 600_000;

/** AES key length in bytes (32 bytes = 256-bit) */
export const AES_KEY_LENGTH = 32;

/** Compression mode */
export type CompressionMode = 'brotli' | '7fold';

/** Supported encryption algorithms */
export type EncryptionAlgo = 'aes-256-gcm';

/** Metadata stored (unencrypted) in the CRAFT package header */
export interface CraftMetadata {
  /** Original filename */
  originalName: string;
  /** Original file size in bytes */
  originalSize: number;
  /** Original MIME type */
  originalMime: string;
  /** Size after compression (before encryption) */
  compressedSize: number;
  /** Compression mode used */
  compressionMode: CompressionMode;
  /** Winning strategy name (only for 7fold mode) */
  compressionStrategyName?: string;
  /** Encryption algorithm used */
  encryptionAlgo: EncryptionAlgo;
  /** SHA-256 hex digest of the original file */
  originalChecksum: string;
  /** ISO timestamp of when the package was created */
  createdAt: string;
  /** CRAFT format version */
  version: number;
}

/** Result of a Nano (compress + encrypt) operation */
export interface NanoResult {
  /** The .craft package buffer */
  buffer: Buffer;
  /** Metadata about the operation */
  metadata: CraftMetadata;
  /** Compression ratio (0-1, lower is better) */
  compressionRatio: number;
  /** Space saved in bytes */
  spaceSaved: number;
  /** Space saved as percentage */
  spaceSavedPercent: number;
  /** All strategy benchmarks (only in 7fold mode) */
  strategyBenchmarks?: Array<{
    strategy: number;
    name: string;
    size: number;
  }>;
}

/** Result of a Macro (decrypt + decompress) operation */
export interface MacroResult {
  /** The restored original file buffer */
  buffer: Buffer;
  /** Metadata extracted from the package */
  metadata: CraftMetadata;
  /** Whether SHA-256 integrity verification passed */
  integrityVerified: boolean;
}

/** Options for the Nano operation */
export interface NanoOptions {
  /** Compression mode: '7fold' (default) or 'brotli' (legacy) */
  compressionMode?: CompressionMode;
  /** Encryption algorithm (default: 'aes-256-gcm') */
  encryptionAlgo?: EncryptionAlgo;
}
