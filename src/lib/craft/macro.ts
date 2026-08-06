/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/macro — Decrypt + Decompress Pipeline
 *  The Living Canvas Edition — 7-Fold Compression
 * ═══════════════════════════════════════════════════════════════
 *
 *  Pipeline:
 *    .craft Package ──► AES-256-GCM Decrypt ──► 7-Fold Decompress ──► Raw Data
 *    (crafted)          (unveiled)               (re-inflated ×7)      (living)
 *
 *  Supports both v1 (legacy Brotli) and v2 (7-fold) packages.
 *  The version byte in the package header determines the
 *  decompression strategy.
 *
 *  Also supports encrypted metadata (v2 with metadataEncrypted flag).
 *  When metadata is encrypted, a second set of salt/iv/authTag
 *  precedes the encrypted metadata blob.
 */

import { decryptWithKey, decompress, decompress7Async, decryptMetadataWithKey, deriveKeyAsync } from './codec';
import { verify } from './integrity';
import {
  CRAFT_MAGIC,
  AUTH_TAG_LENGTH,
  IV_LENGTH,
  SALT_LENGTH,
  CraftMetadata,
  MacroResult,
  METADATA_ENCRYPTED_FLAG,
  METADATA_LENGTH_MASK,
} from './types';

/** Minimum supported CRAFT version */
const MIN_VERSION = 1;
/** Maximum supported CRAFT version */
const MAX_VERSION = 3;
/** First version that stores an explicit metadata-encrypted flag instead of sniffing content */
const FIRST_EXPLICIT_FLAG_VERSION = 3;

/** Maximum metadata size (1MB) — prevents DoS from malicious metadata length */
const MAX_METADATA_SIZE = 1 * 1024 * 1024;

/** Crypto parameter overhead: SALT(16) + IV(12) + AUTH_TAG(16) = 44 bytes */
const CRYPTO_OVERHEAD = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;

/**
 * LEGACY (v1/v2 only): guess whether the metadata at the given offset is
 * encrypted or plaintext by sniffing the first byte for a JSON opening
 * brace '{' (0x7B). This heuristic is ambiguous — encrypted metadata
 * begins with a random salt byte, which has a 1-in-256 chance of also
 * being 0x7B, in which case this misidentifies encrypted metadata as
 * plaintext and the package becomes unreadable even with the correct
 * passphrase. v3+ packages avoid this entirely via an explicit flag bit
 * in the ML field (see resolveMetadataEncryption below) — this function
 * exists only to keep reading older v1/v2 packages that already used it.
 */
function isMetadataPlaintext(craftBuffer: Buffer, offset: number, metadataLength: number): boolean {
  if (offset >= craftBuffer.length) return false;
  const firstByte = craftBuffer[offset];
  return firstByte === 0x7B; // '{'
}

/**
 * Determine whether a package's metadata is encrypted, and the true
 * metadata section length, given the package version and the raw ML
 * field read from the header.
 *
 * v3+: bit 31 of the raw ML field is an explicit flag — no guessing.
 * v1/v2: falls back to the legacy content-sniffing heuristic above.
 */
function resolveMetadataEncryption(
  version: number,
  rawMetadataLength: number,
  craftBuffer: Buffer,
  offset: number,
): { isEncrypted: boolean; metadataLength: number } {
  if (version >= FIRST_EXPLICIT_FLAG_VERSION) {
    return {
      isEncrypted: (rawMetadataLength & METADATA_ENCRYPTED_FLAG) !== 0,
      metadataLength: rawMetadataLength & METADATA_LENGTH_MASK,
    };
  }
  return {
    isEncrypted: !isMetadataPlaintext(craftBuffer, offset, rawMetadataLength),
    metadataLength: rawMetadataLength,
  };
}

/**
 * A .craft package parsed into its sections WITHOUT any decryption.
 *
 * Splitting parsing from decryption is what lets nano() self-verify with keys
 * it already derived (macroWithKeys) instead of re-running PBKDF2 on the
 * package salts — see macro() and macroWithKeys below.
 */
interface ParsedPackage {
  version: number;
  metadataEncrypted: boolean;
  /** Parsed plaintext metadata (only present when metadataEncrypted is false) */
  metadata?: CraftMetadata;
  metaSalt?: Buffer;
  metaIv?: Buffer;
  metaAuthTag?: Buffer;
  encryptedMeta?: Buffer;
  salt: Buffer;
  iv: Buffer;
  authTag: Buffer;
  encrypted: Buffer;
}

/**
 * Parse and validate the header of a .craft package.
 * Supports v1, v2 and v3 formats, with encrypted or plaintext metadata.
 * Does NOT decrypt anything — the caller derives keys and decrypts.
 *
 * @internal
 */
function parsePackage(craftBuffer: Buffer): ParsedPackage {
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
  if (offset + 4 > craftBuffer.length) {
    throw new Error(
      'Invalid CRAFT package: truncated header — cannot read metadata length.'
    );
  }
  const rawMetadataLength = craftBuffer.readUInt32BE(offset);
  offset += 4;

  const { isEncrypted, metadataLength } = resolveMetadataEncryption(version, rawMetadataLength, craftBuffer, offset);
  const isPlaintext = !isEncrypted;

  // Bounds check: maximum metadata size (1MB)
  if (metadataLength > MAX_METADATA_SIZE) {
    throw new Error(
      `Invalid CRAFT package: metadata length (${metadataLength} bytes) exceeds ` +
      `maximum allowed size (${MAX_METADATA_SIZE} bytes). This may be a malformed or malicious package.`
    );
  }

  let metadataEncrypted: boolean;
  let metadata: CraftMetadata | undefined;
  let metaSalt: Buffer | undefined;
  let metaIv: Buffer | undefined;
  let metaAuthTag: Buffer | undefined;
  let encryptedMeta: Buffer | undefined;

  if (isPlaintext) {
    // Plaintext metadata format
    // Validate that offset + metadataLength doesn't exceed buffer
    if (offset + metadataLength > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: metadata extends beyond package boundary. ' +
        'The file may be truncated or corrupted.'
      );
    }

    const metadataJson = craftBuffer.subarray(offset, offset + metadataLength).toString('utf-8');
    try {
      metadata = JSON.parse(metadataJson);
    } catch {
      throw new Error(
        'Invalid CRAFT package: metadata is not valid JSON. ' +
        'The file may be corrupted.'
      );
    }
    offset += metadataLength;
    metadataEncrypted = false;

    // Validate remaining buffer has enough for crypto params + data
    if (offset + CRYPTO_OVERHEAD > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: insufficient data for crypto parameters. ' +
        'The file may be truncated or corrupted.'
      );
    }
  } else {
    // Encrypted metadata format:
    // META_SALT(16) + META_IV(12) + META_AUTHTAG(16) + ENCRYPTED_META(variable)
    // The metadataLength includes the crypto prefix (44 bytes) + encrypted blob
    metadataEncrypted = true;

    // Validate we have at least the crypto prefix
    if (offset + CRYPTO_OVERHEAD > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: insufficient data for metadata crypto parameters. ' +
        'The file may be truncated or corrupted.'
      );
    }

    metaSalt = craftBuffer.subarray(offset, offset + SALT_LENGTH);
    offset += SALT_LENGTH;

    metaIv = craftBuffer.subarray(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    metaAuthTag = craftBuffer.subarray(offset, offset + AUTH_TAG_LENGTH);
    offset += AUTH_TAG_LENGTH;

    // The remaining metadata bytes are the encrypted blob
    const encryptedMetaLength = metadataLength - CRYPTO_OVERHEAD;
    if (encryptedMetaLength <= 0) {
      throw new Error(
        'Invalid CRAFT package: encrypted metadata is empty or too small.'
      );
    }

    if (offset + encryptedMetaLength > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: encrypted metadata extends beyond package boundary. ' +
        'The file may be truncated or corrupted.'
      );
    }

    encryptedMeta = craftBuffer.subarray(offset, offset + encryptedMetaLength);
    offset += encryptedMetaLength;

    // Validate remaining buffer has enough for data crypto params + data
    if (offset + CRYPTO_OVERHEAD > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: insufficient data for payload crypto parameters. ' +
        'The file may be truncated or corrupted.'
      );
    }
  }

  // Read data crypto parameters
  const salt = craftBuffer.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;

  const iv = craftBuffer.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;

  const authTag = craftBuffer.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;

  // Remaining bytes are the encrypted payload
  const encrypted = craftBuffer.subarray(offset);

  // Validate that encrypted payload is not empty
  if (encrypted.length === 0) {
    throw new Error(
      'Invalid CRAFT package: encrypted payload is empty. ' +
      'The file may be truncated or corrupted.'
    );
  }

  return {
    version,
    metadataEncrypted,
    metadata,
    metaSalt,
    metaIv,
    metaAuthTag,
    encryptedMeta,
    salt,
    iv,
    authTag,
    encrypted,
  };
}

/**
 * Decrypt the encrypted-metadata section of a parsed package with an
 * already-derived key. Maps GCM auth-tag failures to a passphrase error.
 */
function decryptMetadataSection(pkg: ParsedPackage, metaKey: Buffer): CraftMetadata {
  try {
    const decryptedMetaJson = decryptMetadataWithKey(
      pkg.encryptedMeta as Buffer,
      metaKey,
      pkg.metaIv as Buffer,
      pkg.metaAuthTag as Buffer,
    );
    const parsed = JSON.parse(decryptedMetaJson.toString('utf-8')) as CraftMetadata;
    parsed.metadataEncrypted = true;
    return parsed;
  } catch (err: unknown) {
    if (err instanceof Error && (err.message.includes('auth tag') || err.message.includes('Unsupported state') || err.message.includes('EVP_DecryptFinal'))) {
      throw new Error(
        'Metadata decryption failed — the passphrase is incorrect.'
      );
    }
    throw new Error(
      'Invalid CRAFT package: failed to decrypt or parse metadata. ' +
      'The file may be corrupted or the passphrase is incorrect.'
    );
  }
}

/** Validate that a buffer could plausibly be a .craft package. */
function assertValidCraftPackage(craftBuffer: Buffer): void {
  if (!Buffer.isBuffer(craftBuffer) || craftBuffer.length < 20) {
    throw new Error(
      'Invalid CRAFT package: too small to be a valid .craft file. ' +
      'Minimum package size is 20 bytes (magic + version + metadata + crypto params).'
    );
  }
}

/**
 * Finish the Macro pipeline with the payload already decrypted:
 * decompress (7-fold vs Brotli) then verify the SHA-256 checksum.
 * Shared by macro() and macroWithKeys().
 */
async function finishMacro(metadata: CraftMetadata, compressed: Buffer): Promise<MacroResult> {
  // The compressionMode in metadata tells us exactly how to decompress:
  //   'brotli' = raw Brotli (no strategy byte prefix)
  //   '7fold'  = 7-fold adaptive (strategy byte prefix)
  // The 7-fold path uses decompress7Async so the decode runs on the libuv
  // threadpool (bounded blocking: it never stalls the event loop).
  let restored: Buffer;
  if (metadata.compressionMode === '7fold') {
    restored = await decompress7Async(compressed);
  } else {
    restored = decompress(compressed);
  }

  const integrityVerified = verify(restored, metadata.originalChecksum);

  if (!integrityVerified) {
    throw new Error(
      'INTEGRITY FAILURE: SHA-256 checksum mismatch! ' +
      'The restored data does not match the original. ' +
      'This could indicate data corruption or an incorrect passphrase.'
    );
  }

  return {
    buffer: restored,
    metadata,
    integrityVerified,
  };
}

/**
 * Execute the Macro pipeline: decrypt then decompress.
 *
 * Automatically detects package version and applies the correct
 * decompression strategy (v1 = Brotli, v2 = 7-fold adaptive).
 * Also automatically detects encrypted vs plaintext metadata.
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
  assertValidCraftPackage(craftBuffer);
  if (!passphrase || passphrase.length === 0) {
    throw new Error('Passphrase is required for Macro extraction.');
  }
  if (passphrase.length < 12) {
    throw new Error('Passphrase must be at least 12 characters for secure decryption.');
  }

  // Step 1: Parse the .craft package (structure + validation, no decryption)
  const pkg = parsePackage(craftBuffer);

  // Step 2: Derive keys and decrypt. The metadata and payload each carry
  // their own random salt, so each requires its own PBKDF2 derivation.
  let metadata: CraftMetadata;
  if (pkg.metadataEncrypted) {
    const { key: metaKey } = await deriveKeyAsync(passphrase, pkg.metaSalt as Buffer);
    metadata = decryptMetadataSection(pkg, metaKey);
  } else {
    metadata = pkg.metadata as CraftMetadata;
  }

  const { key: dataKey } = await deriveKeyAsync(passphrase, pkg.salt);
  const compressed = decryptWithKey(pkg.encrypted, dataKey, pkg.iv, pkg.authTag);

  // Step 3: Decompress + verify integrity
  return await finishMacro(metadata, compressed);
}

/**
 * Execute the Macro pipeline with already-derived keys.
 *
 * Identical to `macro()` except the caller supplies the derived metadata and
 * data keys instead of a passphrase, so no PBKDF2 derivation runs here. Used
 * by nano()'s self-verification: it already holds the exact keys it just
 * derived, and re-deriving them from the package salts would double the
 * dominant cost of the whole operation for zero extra assurance. Reuse is
 * safe because the keys come from the same PBKDF2-SHA256 (600,000 iterations,
 * 16-byte salt) derivation and are fully determined by the package salts.
 *
 * @param craftBuffer — The .craft package buffer
 * @param keys — { metaKey?, dataKey }: dataKey is always required; metaKey is
 *               required only when the package has encrypted metadata
 * @returns MacroResult with the restored data and verification status
 */
export async function macroWithKeys(
  craftBuffer: Buffer,
  keys: { metaKey?: Buffer; dataKey: Buffer },
): Promise<MacroResult> {
  assertValidCraftPackage(craftBuffer);

  const pkg = parsePackage(craftBuffer);

  let metadata: CraftMetadata;
  if (pkg.metadataEncrypted) {
    if (!keys.metaKey) {
      throw new Error('Invalid CRAFT package: encrypted metadata requires a metaKey to decrypt.');
    }
    metadata = decryptMetadataSection(pkg, keys.metaKey);
  } else {
    metadata = pkg.metadata as CraftMetadata;
  }

  const compressed = decryptWithKey(pkg.encrypted, keys.dataKey, pkg.iv, pkg.authTag);
  return await finishMacro(metadata, compressed);
}

/**
 * Peek at the metadata of a .craft package without decrypting.
 * If metadata is encrypted, returns a redacted metadata object
 * with placeholder values for sensitive fields.
 */
export function peekMetadata(craftBuffer: Buffer): CraftMetadata {
  let offset = 0;

  // Validate magic bytes
  if (craftBuffer.length < 11) {
    throw new Error('Invalid CRAFT package: too small to contain valid header.');
  }

  const magic = craftBuffer.subarray(offset, offset + 6);
  if (!magic.equals(CRAFT_MAGIC)) {
    throw new Error('Invalid CRAFT package: magic bytes mismatch.');
  }
  const version = craftBuffer[offset + 6];
  offset += 7; // magic(6) + version(1)

  // Read metadata length with bounds checking
  if (offset + 4 > craftBuffer.length) {
    throw new Error('Invalid CRAFT package: truncated header — cannot read metadata length.');
  }
  const rawMetadataLength = craftBuffer.readUInt32BE(offset);
  offset += 4;

  const { isEncrypted, metadataLength } = resolveMetadataEncryption(version, rawMetadataLength, craftBuffer, offset);
  const isPlaintext = !isEncrypted;

  // Bounds check: maximum metadata size
  if (metadataLength > MAX_METADATA_SIZE) {
    throw new Error(
      `Invalid CRAFT package: metadata length (${metadataLength} bytes) exceeds ` +
      `maximum allowed size (${MAX_METADATA_SIZE} bytes).`
    );
  }

  if (isPlaintext) {
    // Plaintext metadata — can read directly
    if (offset + metadataLength > craftBuffer.length) {
      throw new Error(
        'Invalid CRAFT package: metadata extends beyond package boundary.'
      );
    }
    const metadataJson = craftBuffer.subarray(offset, offset + metadataLength).toString('utf-8');
    try {
      return JSON.parse(metadataJson);
    } catch {
      throw new Error('Invalid CRAFT package: metadata is not valid JSON.');
    }
  } else {
    // Encrypted metadata — return redacted metadata without passphrase
    return {
      originalName: '[encrypted]',
      originalSize: 0,
      originalMime: '[encrypted]',
      compressedSize: 0,
      compressionMode: '7fold',
      encryptionAlgo: 'aes-256-gcm',
      originalChecksum: '[encrypted]',
      createdAt: '[encrypted]',
      version,
      metadataEncrypted: true,
    };
  }
}
