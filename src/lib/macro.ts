/**
 * @craft/macro — Decrypt + Decompress Pipeline
 *
 * Pipeline:
 *   .craft Package → AES-256-GCM Decrypt → 7-Fold Decompress → Raw Data
 *
 * Supports both v1 (legacy Brotli) and v2 (7-fold) packages.
 * The version byte in the package header determines the
 * decompression strategy.
 */

import { decryptAsync, decompress, decompress7 } from './codec';
import { verify } from './integrity';
import {
  CRAFT_MAGIC,
  AUTH_TAG_LENGTH,
  IV_LENGTH,
  SALT_LENGTH,
  CraftMetadata,
  MacroResult,
} from './types';

/** Minimum supported CRAFT version */
const MIN_VERSION = 1;
/** Maximum supported CRAFT version */
const MAX_VERSION = 2;

/**
 * Parse and validate the header of a .craft package.
 * Supports v1 and v2 formats.
 *
 * @internal
 */
function parsePackage(craftBuffer: Buffer): {
  version: number;
  metadata: CraftMetadata;
  salt: Buffer;
  iv: Buffer;
  authTag: Buffer;
  encrypted: Buffer;
} {
  let offset = 0;

  // Validate magic bytes
  const magic = craftBuffer.subarray(offset, offset + 6);
  if (!magic.equals(CRAFT_MAGIC)) {
    throw new Error(
      'Invalid CRAFT package: magic bytes mismatch. ' +
      'This is not a valid .craft file.'
    );
  }
  offset += 6;

  // Read and validate version
  const version = craftBuffer[offset];
  if (version < MIN_VERSION || version > MAX_VERSION) {
    throw new Error(
      `Unsupported CRAFT version: ${version}. ` +
      `Supported versions: ${MIN_VERSION}-${MAX_VERSION}.`
    );
  }
  offset += 1;

  // Read metadata length
  const metadataLength = craftBuffer.readUInt32BE(offset);
  offset += 4;

  // Parse metadata JSON
  const metadataJson = craftBuffer.subarray(offset, offset + metadataLength).toString('utf-8');
  const metadata: CraftMetadata = JSON.parse(metadataJson);
  offset += metadataLength;

  // Read crypto parameters
  const salt = craftBuffer.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;

  const iv = craftBuffer.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;

  const authTag = craftBuffer.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;

  // Remaining bytes are the encrypted payload
  const encrypted = craftBuffer.subarray(offset);

  return { version, metadata, salt, iv, authTag, encrypted };
}

/**
 * Execute the Macro pipeline: decrypt then decompress.
 *
 * Automatically detects package version and applies the correct
 * decompression strategy (v1 = Brotli, v2 = 7-fold adaptive).
 *
 * @param craftBuffer — The .craft package buffer
 * @param passphrase — Decryption passphrase
 * @returns MacroResult with the restored data and verification status
 */
export async function macro(
  craftBuffer: Buffer,
  passphrase: string,
): Promise<MacroResult> {
  // Input validation
  if (!Buffer.isBuffer(craftBuffer) || craftBuffer.length < 20) {
    throw new Error(
      'Invalid CRAFT package: too small to be a valid .craft file. ' +
      'Minimum package size is 20 bytes (magic + version + metadata + crypto params).'
    );
  }
  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase is required for Macro extraction.');
  }

  // Step 1: Parse the .craft package
  const { version, metadata, salt, iv, authTag, encrypted } = parsePackage(craftBuffer);

  // Step 2: Decrypt the compressed data.
  // Metadata JSON is passed as AAD to verify header integrity.
  // Async variant avoids blocking the event loop during PBKDF2.
  const metadataJson = Buffer.from(JSON.stringify(metadata), 'utf-8');
  const compressed = await decryptAsync(encrypted, passphrase, iv, authTag, salt, metadataJson);

  // Step 3: Decompress based on compression mode from metadata.
  // The compressionMode field is more reliable than version alone,
  // since v2 packages can use either mode.
  let restored: Buffer;
  if (metadata.compressionMode === '7fold') {
    // 7-fold adaptive compression (strategy byte prefix)
    restored = decompress7(compressed);
  } else {
    // 'brotli' or any legacy mode: raw Brotli decompression
    restored = decompress(compressed);
  }

  // Step 4: Verify integrity via SHA-256 checksum.
  // Returns false rather than throwing so callers (e.g. web UI) can
  // show a warning and still offer the data for download. Fatal errors
  // (wrong passphrase, corrupt header) are thrown earlier.
  const integrityVerified = verify(restored, metadata.originalChecksum);

  return {
    buffer: restored,
    metadata,
    integrityVerified,
  };
}

/**
 * Peek at the metadata of a .craft package without decrypting.
 * Validates magic bytes and minimum buffer size before reading.
 */
export function peekMetadata(craftBuffer: Buffer): CraftMetadata {
  if (!Buffer.isBuffer(craftBuffer) || craftBuffer.length < 11) {
    throw new Error('Invalid CRAFT package: buffer too small to contain a valid header.');
  }

  let offset = 0;

  const magic = craftBuffer.subarray(offset, offset + 6);
  if (!magic.equals(CRAFT_MAGIC)) {
    throw new Error('Invalid CRAFT package: magic bytes mismatch.');
  }
  offset += 6;

  const version = craftBuffer[offset];
  if (version < MIN_VERSION || version > MAX_VERSION) {
    throw new Error(
      `Unsupported CRAFT version: ${version}. Supported versions: ${MIN_VERSION}-${MAX_VERSION}.`
    );
  }
  offset += 1; // skip version byte

  const metadataLength = craftBuffer.readUInt32BE(offset);
  offset += 4;

  if (craftBuffer.length < offset + metadataLength) {
    throw new Error('Invalid CRAFT package: metadata length exceeds buffer size.');
  }

  const metadataJson = craftBuffer.subarray(offset, offset + metadataLength).toString('utf-8');
  return JSON.parse(metadataJson);
}
