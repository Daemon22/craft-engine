/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/nano — Compress + Encrypt Pipeline
 *  The Living Canvas Edition — 7-Fold Compression
 * ═══════════════════════════════════════════════════════════════
 *
 *  Pipeline (7-Fold):
 *    Raw Data ──► 7-Fold Compress ──► AES-256-GCM Encrypt ──► .craft Package
 *    (fullness)    (weightless ×7)     (inviolate)             (crafted)
 *
 *  The 7-fold engine tries all compression strategies in parallel
 *  and selects the one that produces the smallest output. The
 *  winning strategy ID is embedded in the compressed stream so
 *  decompression knows exactly how to reverse it.
 */

import { compress, compress7Async, encryptWithKey, encryptMetadataWithKey, deriveKeyAsync } from './codec';
import { macroWithKeys } from './macro';
import { checksum } from './integrity';
import {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  CraftMetadata,
  NanoResult,
  NanoOptions,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  METADATA_ENCRYPTED_FLAG,
} from './types';
import {
  validateCredentialKey,
  credentialKeySecret,
} from './credentials';

/**
 * Resolve the effective encryption secret (the PBKDF2 input) from either a
 * passphrase or a credential key. A credential key is pre-hashed with a
 * domain-separation prefix before reaching PBKDF2 (see credentials.ts).
 */
function resolveSecret(
  passphrase: string,
  options?: NanoOptions,
): string {
  if (options?.credentialKey) {
    const v = validateCredentialKey(options.credentialKey);
    if (!v.valid) throw new Error(v.errors.join(' '));
    return credentialKeySecret(options.credentialKey);
  }
  if (!passphrase || passphrase.length < 12) {
    throw new Error('Passphrase must be at least 12 characters for secure encryption.');
  }
  return passphrase;
}

/**
 * Execute the Nano pipeline with 7-fold adaptive compression.
 *
 * @param data — The raw input data to craft
 * @param originalName — Original filename for metadata
 * @param originalMime — Original MIME type for metadata
 * @param passphrase — Encryption passphrase (or empty when options.credentialKey is set)
 * @param options — Optional compression/encryption settings
 * @returns NanoResult with the .craft buffer and operation stats
 */
export async function nano(
  data: Buffer,
  originalName: string,
  originalMime: string,
  passphrase: string,
  options?: NanoOptions,
): Promise<NanoResult> {
  // Input validation
  if (!Buffer.isBuffer(data) || data.length === 0) {
    throw new Error('Cannot craft empty data. Provide non-empty input to Craft Nano.');
  }
  if (options?.credentialKey) {
    const v = validateCredentialKey(options.credentialKey);
    if (!v.valid) throw new Error(v.errors.join(' '));
  } else if (!passphrase || passphrase.length < 12) {
    throw new Error('Passphrase must be at least 12 characters for secure encryption.');
  }
  if (!originalName || originalName.trim().length === 0) {
    throw new Error('Original filename is required for package metadata.');
  }

  const secret = resolveSecret(passphrase, options);

  // Fold 1: Compute integrity checksum
  const originalChecksum = checksum(data);

  // Fold 2-7: Compress with the selected mode
  const mode = options?.compressionMode ?? '7fold';
  let compressed: Buffer;
  let compressionStrategyName: string | undefined;
  let strategyBenchmarks: Array<{ strategy: number; name: string; size: number }> | undefined;

  if (mode === '7fold') {
    // Async engine: the Brotli/Zstd strategy passes run on the libuv
    // threadpool, so compressing a large file no longer blocks the event loop.
    const result = await compress7Async(data);
    compressed = result.data;
    compressionStrategyName = result.strategyName;
    strategyBenchmarks = result.allResults;
  } else {
    compressed = compress(data);
  }

  // Fold 3: AES-256-GCM encrypt the compressed data.
  // Derive each key ONCE and reuse it for the self-verification below
  // (macroWithKeys) instead of macro() re-deriving from the package salts.
  // The package stores the salts, so macro() reproduces the exact same keys
  // from the passphrase — the format and security parameters are unchanged;
  // only the redundant re-derivations are removed (4 → 2 for nano()).
  const { key: dataKey, salt } = await deriveKeyAsync(secret);
  const { encrypted, iv, authTag } = encryptWithKey(compressed, dataKey, salt);

  // Determine if metadata should be encrypted (default: true)
  const shouldEncryptMetadata = options?.encryptMetadata !== false;

  // Build metadata
  const metadata: CraftMetadata = {
    originalName,
    originalSize: data.length,
    originalMime,
    compressedSize: compressed.length,
    compressionMode: mode,
    compressionStrategyName,
    encryptionAlgo: options?.encryptionAlgo ?? 'aes-256-gcm',
    originalChecksum,
    createdAt: new Date().toISOString(),
    version: CRAFT_VERSION,
    metadataEncrypted: shouldEncryptMetadata,
  };

  // Serialize metadata
  const metadataJson = Buffer.from(JSON.stringify(metadata), 'utf-8');

  // Derive the metadata key only when metadata will actually be encrypted
  let metaKey: Buffer | undefined;
  let metaSalt: Buffer | undefined;
  if (shouldEncryptMetadata) {
    const metaKeyResult = await deriveKeyAsync(secret);
    metaKey = metaKeyResult.key;
    metaSalt = metaKeyResult.salt;
  }

  // Assemble the .craft package
  let buffer: Buffer;

  if (shouldEncryptMetadata) {
    // Encrypted metadata format:
    // MAGIC(6) + VER(1) + ML(4) + META_SALT(16) + META_IV(12) + META_AUTHTAG(16) + ENCRYPTED_META(variable) + DATA_SALT(16) + DATA_IV(12) + DATA_AUTHTAG(16) + ENCRYPTED_DATA(variable)
    // ML = total length of encrypted metadata section (crypto prefix + encrypted blob)
    const metaResult = encryptMetadataWithKey(metadataJson, metaKey as Buffer, metaSalt as Buffer);
    const metaSectionLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + metaResult.encrypted.length;
    const metadataLength = Buffer.alloc(4);
    // Bit 31 explicitly marks this section as encrypted metadata (v3+) — see types.ts.
    // Coerce to unsigned: in JS, `x | 0x80000000` yields a signed negative number.
    metadataLength.writeUInt32BE(((metaSectionLength & 0x7fffffff) | METADATA_ENCRYPTED_FLAG) >>> 0, 0);

    buffer = Buffer.concat([
      CRAFT_MAGIC,
      Buffer.from([CRAFT_VERSION]),
      metadataLength,
      metaResult.metaSalt,
      metaResult.metaIv,
      metaResult.metaAuthTag,
      metaResult.encrypted,
      salt,
      iv,
      authTag,
      encrypted,
    ]);
  } else {
    // Plaintext metadata format (backward compat):
    // MAGIC(6) + VER(1) + ML(4) + META_JSON(variable) + DATA_SALT(16) + DATA_IV(12) + DATA_AUTHTAG(16) + ENCRYPTED_DATA(variable)
    const metadataLength = Buffer.alloc(4);
    // Bit 31 left clear marks this section as plaintext metadata (v3+) — see types.ts.
    metadataLength.writeUInt32BE(metadataJson.length & 0x7fffffff, 0);

    buffer = Buffer.concat([
      CRAFT_MAGIC,
      Buffer.from([CRAFT_VERSION]),
      metadataLength,
      metadataJson,
      salt,
      iv,
      authTag,
      encrypted,
    ]);
  }

  const compressionRatio = data.length > 0 ? buffer.length / data.length : 0;
  const spaceSaved = Math.max(0, data.length - buffer.length);

  // Self-verification (on by default — see NanoOptions.verify docs). Catches
  // a broken compression/decompression pairing right now, while the
  // original data is still available to compare against, instead of only
  // finding out when someone tries to restore the file later.
  const shouldVerify = options?.verify !== false;
  if (shouldVerify) {
    let restoredOk = false;
    let verifyError: string | undefined;
    try {
      const restored = await macroWithKeys(buffer, { metaKey, dataKey });
      restoredOk = restored.integrityVerified && restored.buffer.equals(data);
    } catch (err) {
      verifyError = err instanceof Error ? err.message : String(err);
    }
    if (!restoredOk) {
      throw new Error(
        'CRAFT self-verification failed: the package that was just built did ' +
        'not decrypt/decompress back to the original data' +
        (verifyError ? ` (${verifyError})` : '') +
        `. Strategy used: ${compressionStrategyName ?? mode}. This package was ` +
        'NOT returned — nothing was written or lost, but please report this ' +
        '(it indicates a bug in the compression/decryption pipeline, not a ' +
        'problem with your input).'
      );
    }
  }

  return {
    buffer,
    metadata,
    compressionRatio,
    spaceSaved,
    spaceSavedPercent: data.length > 0
      ? Math.max(0, (1 - compressionRatio) * 100)
      : 0,
    strategyBenchmarks,
  };
}
