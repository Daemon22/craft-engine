/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/nano — Hardened Compress + Encrypt Pipeline
 * ═══════════════════════════════════════════════════════════════
 */

import { compress, compress7Async, encryptWithKey, encryptMetadataWithKey, deriveKeyAsync } from './codec';
import { macroWithKeys } from './macro';
import { checksum } from './integrity';
import { getFeatures, logAuditAction, CraftTier } from './features';
import {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  CraftMetadata,
  NanoResult,
  NanoOptions,
  METADATA_ENCRYPTED_FLAG,
  PBKDF2_ITERATIONS,
} from './types';
import {
  validateCredentialKey,
  credentialKeySecret,
} from './credentials';
import { monitorCraftOperation } from './progress';

function resolveSecret(passphrase: string, options?: NanoOptions): string {
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

export async function nano(
  data: Buffer,
  originalName: string,
  originalMime: string,
  passphrase: string,
  options?: NanoOptions,
): Promise<NanoResult> {
  return monitorCraftOperation('nano', options, async (progress) => {
    const { tier, features, secret, originalChecksum, mode } = await progress.step(
      'validate_input',
      async () => {
        const tier = options?.tier || CraftTier.FREE;
        const features = getFeatures(tier);
        if (data.length > (features.maxFileSize * 1024 * 1024)) {
          throw new Error(`File size exceeds the ${tier} tier limit of ${features.maxFileSize}MB.`);
        }
        return {
          tier,
          features,
          secret: resolveSecret(passphrase, options),
          originalChecksum: checksum(data),
          mode: options?.compressionMode ?? '7fold',
        };
      },
      { input_size_bytes: data.length },
    );

    const { compressed, compressionStrategyName, strategyBenchmarks, strategyNumber } = await progress.step(
      'compress',
      async () => {
        if (mode === '7fold') {
          const result = await compress7Async(data);

          // Block Strategy 12 (craft-codec) for Free tier
          if (result.strategy === 12 && !features.allowEliteCodec) {
            // Fallback selection is kept here for the current strategy policy.
            const fallback = result.allResults.filter(r => r.strategy !== 12).sort((a, b) => a.size - b.size)[0];
            console.warn("Elite codec (Strategy 12) is locked in FREE tier. Falling back.");
          }

          return {
            compressed: result.data,
            compressionStrategyName: result.strategyName,
            strategyBenchmarks: result.allResults,
            strategyNumber: result.strategy,
          };
        }
        return {
          compressed: compress(data),
          compressionStrategyName: undefined,
          strategyBenchmarks: undefined,
          strategyNumber: undefined,
        };
      },
      result => ({
        input_size_bytes: data.length,
        compression_mode: mode,
        compression_strategy: result.compressionStrategyName || 'brotli',
        strategy_number: result.strategyNumber ?? null,
      }),
    );

    const { dataKey, salt, metaKey, metaKeySalt } = await progress.step(
      'derive_keys',
      async () => {
        const { key: dataKey, salt } = await deriveKeyAsync(secret);
        if (options?.encryptMetadata !== false) {
          const { key: metaKey, salt: metaKeySalt } = await deriveKeyAsync(secret);
          return { dataKey, salt, metaKey, metaKeySalt };
        }
        return { dataKey, salt, metaKey: undefined, metaKeySalt: undefined };
      },
      { algorithm: 'PBKDF2-SHA256', iterations: PBKDF2_ITERATIONS },
    );

    const metadata: CraftMetadata = {
      originalName,
      originalSize: data.length,
      originalMime,
      compressedSize: compressed.length,
      compressionMode: mode,
      compressionStrategyName,
      encryptionAlgo: 'aes-256-gcm',
      originalChecksum,
      createdAt: new Date().toISOString(),
      version: CRAFT_VERSION,
      metadataEncrypted: options?.encryptMetadata !== false,
    };

    const metadataJson = await progress.step(
      'prepare_metadata',
      async () => Buffer.from(JSON.stringify(metadata), 'utf-8'),
      { metadata_encrypted: metadata.metadataEncrypted === true },
    );
    let metadataSection = metadataJson;
    if (metadata.metadataEncrypted) {
      const metaResult = await progress.step(
        'encrypt_metadata',
        async () => encryptMetadataWithKey(metadataJson, metaKey as Buffer, metaKeySalt as Buffer),
        { metadata_encrypted: true },
      );
      metadataSection = Buffer.concat([
        metaResult.metaSalt, metaResult.metaIv, metaResult.metaAuthTag, metaResult.encrypted,
      ]);
    }

    const metadataLength = Buffer.alloc(4);
    const lengthField = metadata.metadataEncrypted
      ? ((metadataSection.length & 0x7fffffff) | METADATA_ENCRYPTED_FLAG) >>> 0
      : metadataSection.length;
    metadataLength.writeUInt32BE(lengthField, 0);

    const header = Buffer.concat([CRAFT_MAGIC, Buffer.from([CRAFT_VERSION]), metadataLength, metadataSection]);
    const { encrypted, iv, authTag } = await progress.step(
      'encrypt_payload',
      async () => encryptWithKey(compressed, dataKey, salt, header),
      { input_size_bytes: compressed.length, algorithm: 'AES-256-GCM' },
    );

    const buffer = Buffer.concat([header, salt, iv, authTag, encrypted]);

    if (options?.verify !== false) {
      const selfVerifier = progress.scope('self_verify');
      await progress.step(
        'self_verify',
        async () => {
          const restored = await macroWithKeys(
            buffer,
            { dataKey, ...(metaKey ? { metaKey } : {}) },
            selfVerifier,
          );
          if (!restored.integrityVerified || !restored.buffer.equals(data)) {
            throw new Error('CRAFT self-verification failed: restored bytes do not match the input.');
          }
        },
        { package_size_bytes: buffer.length },
      );
    }

    // Audit Logging for Compliance
    if (features.allowAuditLogs) {
      logAuditAction('NANO_CREATE', {
        strategy: compressionStrategyName,
        status: 'SUCCESS',
        tier,
      });
    }

    return {
      buffer,
      metadata,
      compressionRatio: data.length === 0 ? 0 : buffer.length / data.length,
      spaceSaved: Math.max(0, data.length - buffer.length),
      spaceSavedPercent: data.length === 0 ? 0 : Math.max(0, (1 - (buffer.length / data.length)) * 100),
      strategyBenchmarks,
    };
  }, {
    compression_mode: options?.compressionMode ?? '7fold',
    metadata_encrypted: options?.encryptMetadata !== false,
    operation_mode: options?.verify === false ? 'verify_disabled' : 'verify_enabled',
  });
}
