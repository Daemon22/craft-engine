/**
 * Compatibility exports for the legacy multi-file archive implementation.
 *
 * The archive container is intentionally implemented once in ../archive.ts;
 * this module preserves the public exports declared by the hardened barrel.
 */
export { archive, extract, peekArchiveMetadata } from '../archive.js';
export type { ArchiveEntry, ArchiveResult, ExtractResult } from '../archive.js';
