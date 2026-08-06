/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/codec — Brotli Compression & AES-256-GCM Encryption
 *  The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  The codec layer provides the two fundamental transformations:
 *
 *  1. Brotli compression — maximum quality shrinks data to its
 *     most weightless form while preserving every bit
 *  2. AES-256-GCM encryption — military-grade authenticated
 *     encryption ensures data remains impenetrable
 *
 *  Key derivation uses PBKDF2-SHA256 with 600,000 iterations
 *  and a random 16-byte salt per operation. This ensures
 *  that identical passphrases produce different keys each time.
 */

import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync } from 'crypto';
import { brotliCompressSync, brotliDecompressSync, constants as zlibConstants } from 'zlib';
import {
  SALT_LENGTH,
  IV_LENGTH,
  AES_KEY_LENGTH,
  PBKDF2_ITERATIONS,
} from './types';

// ─────────────────────────────────────────────────────────────
// Key Derivation
// ─────────────────────────────────────────────────────────────

/**
 * Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256.
 *
 * Each call generates a unique random salt, ensuring that even
 * the same passphrase produces a different key every time.
 * This prevents rainbow table and precomputation attacks.
 *
 * @param passphrase — The user's encryption passphrase
 * @param salt — Optional existing salt (used during decryption)
 * @returns The derived 256-bit key and the salt used
 */
export function deriveKey(passphrase: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  const actualSalt = salt ?? randomBytes(SALT_LENGTH);
  const key = pbkdf2Sync(passphrase, actualSalt, PBKDF2_ITERATIONS, AES_KEY_LENGTH, 'sha256');
  return { key, salt: actualSalt };
}

// ─────────────────────────────────────────────────────────────
// Compression (Brotli) — Legacy single-pass mode
// ─────────────────────────────────────────────────────────────

/** Default Brotli compression options for maximum compression */
const DEFAULT_BROTLI_QUALITY = 11;
const DEFAULT_BROTLI_WINDOW = 24;

/**
 * Compress data using Brotli at maximum quality (legacy single-pass).
 * For the 7-fold adaptive engine, use compress7 from './compress7'.
 */
export function compress(
  data: Buffer,
  quality: number = DEFAULT_BROTLI_QUALITY,
  window: number = DEFAULT_BROTLI_WINDOW,
): Buffer {
  return brotliCompressSync(data, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: quality,
      [zlibConstants.BROTLI_PARAM_LGWIN]: window,
    },
  });
}

/**
 * Decompress Brotli-compressed data — restores original data losslessly.
 */
export function decompress(data: Buffer): Buffer {
  return brotliDecompressSync(data);
}

// Re-export 7-fold compression engine
export { compress7, decompress7 } from './compress7';
export type { Compress7Result, CompressionStrategy } from './compress7';

// ─────────────────────────────────────────────────────────────
// Encryption (AES-256-GCM)
// ─────────────────────────────────────────────────────────────

export interface EncryptResult {
  /** The encrypted ciphertext */
  encrypted: Buffer;
  /** Random initialization vector (12 bytes) */
  iv: Buffer;
  /** Authentication tag (16 bytes) — tamper detection */
  authTag: Buffer;
  /** Random salt used for key derivation (16 bytes) */
  salt: Buffer;
}

/**
 * Encrypt data using AES-256-GCM with a passphrase.
 *
 * Generates a random IV and derives the encryption key via PBKDF2.
 * The authentication tag ensures that any tampering with the
 * ciphertext is detected during decryption.
 *
 * @param data — The data to encrypt
 * @param passphrase — The encryption passphrase
 * @returns Encrypted data with IV, auth tag, and salt
 */
export function encrypt(data: Buffer, passphrase: string): EncryptResult {
  const { key, salt } = deriveKey(passphrase);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag, salt };
}

/**
 * Decrypt AES-256-GCM encrypted data using a passphrase.
 *
 * Verifies integrity via the authentication tag — throws if
 * the data has been tampered with or the passphrase is wrong.
 * This is the "lawless brilliance" made secure: no unauthorized
 * access can pass the auth tag verification.
 *
 * @param encrypted — The encrypted ciphertext
 * @param passphrase — The decryption passphrase
 * @param iv — The initialization vector from encryption
 * @param authTag — The authentication tag from encryption
 * @param salt — The salt used during key derivation
 * @returns Decrypted buffer
 * @throws Error if passphrase is wrong or data is tampered
 */
export function decrypt(
  encrypted: Buffer,
  passphrase: string,
  iv: Buffer,
  authTag: Buffer,
  salt: Buffer,
): Buffer {
  const { key } = deriveKey(passphrase, salt);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted;
}

// ─────────────────────────────────────────────────────────────
// Metadata Encryption — Filename Privacy
// ─────────────────────────────────────────────────────────────

export interface MetadataEncryptResult {
  /** The encrypted metadata ciphertext */
  encrypted: Buffer;
  /** Random salt for metadata key derivation (16 bytes) */
  metaSalt: Buffer;
  /** Random IV for metadata encryption (12 bytes) */
  metaIv: Buffer;
  /** Authentication tag for metadata (16 bytes) */
  metaAuthTag: Buffer;
}

/**
 * Encrypt metadata JSON using the same key derivation but with a different salt.
 * This ensures filenames and other metadata remain private without the passphrase.
 */
export function encryptMetadata(metaJson: Buffer, passphrase: string): MetadataEncryptResult {
  const { key, salt: metaSalt } = deriveKey(passphrase);
  const metaIv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv('aes-256-gcm', key, metaIv);
  const encrypted = Buffer.concat([
    cipher.update(metaJson),
    cipher.final(),
  ]);
  const metaAuthTag = cipher.getAuthTag();

  return { encrypted, metaSalt, metaIv, metaAuthTag };
}

/**
 * Decrypt metadata JSON using the same key derivation with the provided salt.
 */
export function decryptMetadata(
  encryptedMeta: Buffer,
  passphrase: string,
  metaSalt: Buffer,
  metaIv: Buffer,
  metaAuthTag: Buffer,
): Buffer {
  const { key } = deriveKey(passphrase, metaSalt);

  const decipher = createDecipheriv('aes-256-gcm', key, metaIv);
  decipher.setAuthTag(metaAuthTag);

  const decrypted = Buffer.concat([
    decipher.update(encryptedMeta),
    decipher.final(),
  ]);

  return decrypted;
}
