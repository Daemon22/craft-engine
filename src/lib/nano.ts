/**
 * @craft/nano — Compress + Encrypt Pipeline
 *
 * Pipeline:
 *   Raw Data → 7-Fold Compress → AES-256-GCM Encrypt → .craft Package
 *
 * The 7-fold engine tries all compression strategies and selects
 * the smallest output. The strategy ID is embedded in the
 * compressed stream for correct decompression.
 */

import { compress, compress7, encryptAsync } from './codec';
import { checksum } from './integrity';
import {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  CraftMetadata,
  NanoResult,
  NanoOptions,
} from './types';

/**
 * Execute the Nano pipeline: checksum → compress → encrypt → package.
 *
 * @param data — The raw input data
 * @param originalName — Original filename for metadata
 * @param originalMime — Original MIME type for metadata
 * @param passphrase — Encryption passphrase (min 4 characters)
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
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters for secure encryption.');
  }
  if (!originalName || originalName.trim().length === 0) {
    throw new Error('Original filename is required for package metadata.');
  }

  // Step 1: Compute integrity checksum
  const originalChecksum = checksum(data);

  // Step 2: Compress with the selected mode
  const mode = options?.compressionMode ?? '7fold';
  let compressed: Buffer;
  let compressionStrategyName: string | undefined;
  let strategyBenchmarks: Array<{ strategy: number; name: string; size: number }> | undefined;

  if (mode === '7fold') {
    const result = compress7(data);
    compressed = result.data;
    compressionStrategyName = result.strategyName;
    strategyBenchmarks = result.allResults;
  } else {
    compressed = compress(data);
  }

  // Build metadata to pass as AAD (Additional Authenticated Data) to GCM.
  // AAD is authenticated but not encrypted — any tampering with the
  // unencrypted header is detected during decryption.
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
  };

  // Serialize metadata
  const metadataJson = Buffer.from(JSON.stringify(metadata), 'utf-8');
  const metadataLength = Buffer.alloc(4);
  metadataLength.writeUInt32BE(metadataJson.length, 0);

  // Step 3: AES-256-GCM encrypt the compressed data.
  // Metadata JSON is passed as AAD for header tamper detection.
  // Async variant avoids blocking the event loop during PBKDF2 derivation.
  const { encrypted, iv, authTag, salt } = await encryptAsync(compressed, passphrase, metadataJson);

  // Assemble the .craft package
  const buffer = Buffer.concat([
    CRAFT_MAGIC,
    Buffer.from([CRAFT_VERSION]),
    metadataLength,
    metadataJson,
    salt,
    iv,
    authTag,
    encrypted,
  ]);

  const compressionRatio = data.length > 0 ? buffer.length / data.length : 0;
  const spaceSaved = Math.max(0, data.length - buffer.length);

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
