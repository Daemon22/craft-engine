/**
 * ═══════════════════════════════════════════════════════════════
 *  CRAFT — Nano/Macro Encryption & Compression Engine
 *  Package Index — The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  7-Fold Encryption Tool:
 *    1. Brotli Compression — maximum quality (Q11)
 *    2. Delta Encoding — sequential data optimization
 *    3. Move-to-Front — recurring symbol optimization
 *    4. Run-Length Encoding — repeated byte collapse
 *    5. Byte-Pair Encoding — frequent pair replacement
 *    6. AES-256-GCM Encryption — authenticated encryption
 *    7. SHA-256 Integrity — lossless verification
 */

// Easy Facade — One-liners for pack/unpack
export { craft } from './easy';

// Primary Operations
export { nano } from './nano';
export { macro, peekMetadata, macroWithKeys } from './macro';

// Streaming path (v4 — constant-memory, second execution path).
// See docs/streaming-architecture.md and docs/chunk-format.md.
export { nanoStream } from './nanoStream';
export { macroStream, peekStreamMetadata } from './macroStream';
export type {
  StreamMetadata,
  NanoStreamResult,
  MacroStreamResult,
  NanoStreamOptions,
  MacroStreamOptions,
  StreamCodecOptions,
  StreamCompressionStrategy,
  ChunkCipherBag,
} from './streamCore';

// Hardening: environment/pipeline sanity check
export { selfTest } from './self-test';
export type { SelfTestResult } from './self-test';

// Hardening: passive bitrot/corruption detection for archived packages
export {
  computeFixityRecord,
  verifyFixityRecord,
  serializeFixityRecord,
  parseFixityRecord,
  fixitySidecarPath,
} from './fixity';
export type { FixityRecord, FixityCheckResult } from './fixity';

// 7-Fold Compression Engine
// compress7Async/decompress7Async run the Brotli/Zstd passes on the libuv
// threadpool; the sync variants are retained for legacy/sync callers.
export { compress7, decompress7, compress7Async, decompress7Async } from './compress7';
export type { Compress7Result, CompressionStrategy } from './compress7';

// Codec Layer — sync + async crypto (encrypt/decrypt support optional AAD)
export {
  compress,
  decompress,
  encrypt,
  encryptAsync,
  encryptWithKey,
  decrypt,
  decryptAsync,
  decryptWithKey,
  deriveKey,
  deriveKeyAsync,
  encryptMetadata,
  encryptMetadataAsync,
  encryptMetadataWithKey,
  decryptMetadata,
  decryptMetadataAsync,
  decryptMetadataWithKey,
} from './codec';
export type { EncryptResult, MetadataEncryptResult } from './codec';

// Integrity Layer
export { checksum, verify } from './integrity';

// Credential Keys — 7-char alternative to a passphrase (max 3× per char)
export {
  CREDENTIAL_KEY_LENGTH,
  CREDENTIAL_MAX_REPEAT,
  CREDENTIAL_VALUES,
  CREDENTIAL_SPECIALS,
  CREDENTIAL_ALPHABET,
  isValueChar,
  isSpecialChar,
  validateCredentialKey,
  generateCredentialKey,
  rateCredentialKey,
  countValidKeys,
  credentialKeyEntropy,
  credentialKeySecret,
  credentialKey,
  newCredentialKey,
} from './credentials';
export type {
  CredentialCounts,
  CredentialValidation,
  CredentialStrength,
  CredentialRating,
  CredentialEntropy,
  CredentialKeyInput,
} from './credentials';

// Device Passkeys — fingerprint/face unlock (WebAuthn) as an alternative
export {
  toBase64Url,
  fromBase64Url,
  decodeCBOR,
  generateRegistrationOptions,
  generateAuthenticationOptions,
  parseAuthenticatorData,
  coseKeyToPem,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  PasskeyVault,
} from './passkeys';
export type {
  RelyingPartyConfig,
  RegistrationOptions,
  AuthenticationOptions,
  StoredPasskey,
  RegistrationResponse,
  AuthenticationResponse,
  AuthenticatorData,
  VerifiedRegistration,
  VerifiedAuthentication,
  PasskeyVaultData,
  PasskeyVaultConfig,
} from './passkeys';
export { COSE_ALG, COSE_KTY, COSE_CRV, AUTH_FLAGS } from './passkeys';

// Archive (multi-file) support
export { archive, extract, peekArchiveMetadata } from './archive';
export type { ArchiveEntry, ArchiveResult, ExtractResult } from './archive';

// Compression Analytics
export { CompressionAnalytics, globalAnalytics } from './analytics';
export type { CompressionObservation, StrategyStats, AnalyticsReport } from './analytics';

// Types
export type {
  CraftMetadata,
  NanoResult,
  MacroResult,
  NanoOptions,
  CompressionMode,
} from './types';
export {
  CRAFT_MAGIC,
  CRAFT_VERSION,
  CRAFT_ARCHIVE_VERSION,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  PBKDF2_ITERATIONS,
  AES_KEY_LENGTH,
} from './types';
