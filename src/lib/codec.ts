/**
 * @craft/codec — Brotli Compression & AES-256-GCM Encryption
 *
 * Provides two core transformations:
 *   1. Brotli compression at maximum quality (Q11)
 *   2. AES-256-GCM authenticated encryption
 *
 * Key derivation uses PBKDF2-SHA256 with 600,000 iterations
 * and a random 16-byte salt per operation, ensuring that
 * identical passphrases produce different keys each time.
 */

import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync, pbkdf2 } from 'crypto';
import { brotliCompressSync, brotliDecompressSync, constants as zlibConstants } from 'zlib';
import {
  SALT_LENGTH,
  IV_LENGTH,
  AES_KEY_LENGTH,
  PBKDF2_ITERATIONS,
} from './types';

// ── Key Derivation ──────────────────────────────────────────────

/**
 * Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256 (sync).
 * Each call generates a unique random salt, preventing rainbow table
 * and precomputation attacks.
 *
 * Use deriveKeyAsync in server/async contexts to avoid blocking the event loop.
 */
export function deriveKey(passphrase: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  const actualSalt = salt ?? randomBytes(SALT_LENGTH);
  const key = pbkdf2Sync(passphrase, actualSalt, PBKDF2_ITERATIONS, AES_KEY_LENGTH, 'sha256');
  return { key, salt: actualSalt };
}

/**
 * Async variant of deriveKey — runs PBKDF2 off the main thread
 * so it does not block the event loop during key derivation.
 */
export function deriveKeyAsync(passphrase: string, salt?: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
  const actualSalt = salt ?? randomBytes(SALT_LENGTH);
  return new Promise((resolve, reject) => {
    pbkdf2(passphrase, actualSalt, PBKDF2_ITERATIONS, AES_KEY_LENGTH, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve({ key, salt: actualSalt });
    });
  });
}

// ── Compression (Brotli) ───────────────────────────────────────

/** Default Brotli compression options */
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

/** Decompress Brotli-compressed data. */
export function decompress(data: Buffer): Buffer {
  return brotliDecompressSync(data);
}

// Re-export 7-fold compression engine
export { compress7, decompress7 } from './compress7';
export type { Compress7Result, CompressionStrategy } from './compress7';

// ── Encryption (AES-256-GCM) ───────────────────────────────────

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
 * Optional `aad` (Additional Authenticated Data) is authenticated
 * but not encrypted. Pass the serialized metadata here so header
 * tampering is detected on decrypt.
 */
export function encrypt(data: Buffer, passphrase: string, aad?: Buffer): EncryptResult {
  const { key, salt } = deriveKey(passphrase);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag, salt };
}

/**
 * Async variant of encrypt — runs PBKDF2 off the event loop.
 * Prefer this in API route handlers.
 */
export async function encryptAsync(data: Buffer, passphrase: string, aad?: Buffer): Promise<EncryptResult> {
  const { key, salt } = await deriveKeyAsync(passphrase);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
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
 * If `aad` was supplied during encryption, the same value must be
 * passed here; mismatched AAD causes the auth tag check to fail.
 *
 * @throws Error if passphrase is wrong, data is tampered, or AAD mismatches
 */
export function decrypt(
  encrypted: Buffer,
  passphrase: string,
  iv: Buffer,
  authTag: Buffer,
  salt: Buffer,
  aad?: Buffer,
): Buffer {
  const { key } = deriveKey(passphrase, salt);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  if (aad) decipher.setAAD(aad);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted;
}

/** Async variant of decrypt — runs PBKDF2 off the event loop. */
export async function decryptAsync(
  encrypted: Buffer,
  passphrase: string,
  iv: Buffer,
  authTag: Buffer,
  salt: Buffer,
  aad?: Buffer,
): Promise<Buffer> {
  const { key } = await deriveKeyAsync(passphrase, salt);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  if (aad) decipher.setAAD(aad);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
}
