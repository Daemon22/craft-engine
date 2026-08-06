/**
 * ═══════════════════════════════════════════════════════════════
 *  CRAFT — Nano/Macro Encryption & Compression Engine
 *  Type Definitions & Constants — The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  The CRAFT package format (v3 — 7-Fold Compression):
 *
 *  With encrypted metadata (encryptMetadata: true, default):
 *  ┌──────────┬─────────┬──────────┬───────────┬─────────┬─────────────┬───────────────┬──────┬──────┬──────────┬───────────────┐
 *  │ MAGIC(6) │ VER(1)  │ ML(4)    │ META_SALT │ META_IV │ META_AUTHTAG│ ENCRYPTED_META│ SALT │ IV   │ AUTHTAG  │ ENCRYPTED     │
 *  │ "CRAFT1" │ 0x03    │ uint32BE │ 16B       │ 12B     │ 16B         │ variable      │ 16B  │ 12B  │ 16B      │ variable      │
 *  └──────────┴─────────┴──────────┴───────────┴─────────┴─────────────┴───────────────┴──────┴──────┴──────────┴───────────────┘
 *
 *  With plaintext metadata (encryptMetadata: false, backward compat):
 *  ┌──────────┬─────────┬──────────┬──────┬──────┬────┬──────────┬───────────────┐
 *  │ MAGIC(6) │ VER(1)  │ ML(4)    │ META │ SALT │ IV │ AUTHTAG  │ ENCRYPTED     │
 *  │ "CRAFT1" │ 0x03    │ uint32BE │ JSON │ 16B  │12B │ 16B      │ variable      │
 *  └──────────┴─────────┴──────────┴──────┴──────┴────┴──────────┴───────────────┘
 *
 *  ML (metadata length field, v3+): the high bit (bit 31) is an explicit
 *  METADATA_ENCRYPTED flag; the low 31 bits are the section length. Versions
 *  before v3 instead *sniffed* the first metadata byte (checking for '{')
 *  to guess plaintext vs. encrypted — that guess had a ~1/256 chance of
 *  misfiring whenever a random metadata salt happened to start with 0x7B,
 *  permanently corrupting the package. v3 removes that ambiguity by
 *  recording the flag explicitly. Reading v1/v2 packages still uses the
 *  old sniffing heuristic for backward compatibility.
 *
 *  The ENCRYPTED payload contains: [strategy_id(1), ...compressed_data]
 *  where compressed_data = Brotli(pre_processed(original_data))
 *  The strategy_id tells decompression which inverse transforms to apply.
 */

/** Magic bytes identifying a CRAFT package — "CRAFT1" */
export const CRAFT_MAGIC = Buffer.from('CRAFT1');

/** Current CRAFT format version (v3 = 7-fold compression + explicit metadata-encrypted flag) */
export const CRAFT_VERSION = 3;

/** Bit 31 of the ML (metadata length) field: explicit "metadata is encrypted" flag (v3+) */
export const METADATA_ENCRYPTED_FLAG = 0x80000000;

/** Mask to extract the actual metadata section length from the ML field (v3+) */
export const METADATA_LENGTH_MASK = 0x7fffffff;

/** Salt length for PBKDF2 key derivation (16 bytes) */
export const SALT_LENGTH = 16;

/** IV length for AES-256-GCM (12 bytes — NIST recommendation) */
export const IV_LENGTH = 12;

/** Auth tag length for AES-256-GCM (16 bytes = 128-bit tag) */
export const AUTH_TAG_LENGTH = 16;

/** PBKDF2 iterations — 600,000 provides strong resistance against brute-force */
export const PBKDF2_ITERATIONS = 600_000;

/** AES key length in bytes (32 bytes = 256-bit) */
export const AES_KEY_LENGTH = 32;

/** Compression mode */
export type CompressionMode = 'brotli' | '7fold';

/** Supported encryption algorithms */
export type EncryptionAlgo = 'aes-256-gcm';

/** Metadata stored in the CRAFT package header (encrypted or plaintext) */
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
  /** Whether the metadata was stored encrypted in the package */
  metadataEncrypted?: boolean;
}

/** Result of a Nano (compress + encrypt) operation */
export interface NanoResult {
  /** The crafted .craft package buffer */
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
  /** Whether to encrypt the metadata (default: true for filename privacy) */
  encryptMetadata?: boolean;
  /**
   * Whether to self-verify the package immediately after building it, by
   * decrypting+decompressing it in-memory and confirming the result is
   * byte-identical to the original input, before returning it to the
   * caller. Defaults to true. This is deliberately on by default: it
   * catches a broken compression/decompression pairing (a real bug class
   * this codebase has had) at the moment of creation — when the original
   * data is still in hand — rather than leaving it to be discovered later
   * when the only copy left is the possibly-broken package. The cost is
   * one extra decompress+decrypt cycle per call. Set to false only if
   * you've independently verified the pipeline (e.g. a caller that
   * already re-reads and checks the written file itself) and need the
   * throughput.
   */
  verify?: boolean;
}
