/**
 * @craft/archive — Multi-file Archive Support
 *
 * Pack multiple files into a single `.craft` archive package.
 *
 * Archive format (v3):
 *   CRAFT_MAGIC(6) | VERSION(1)=3 |
 *   META_LEN(4) | META_JSON(var) — contains entry names, sizes, checksum |
 *   SALT(16) | IV(12) | AUTH_TAG(16) | ENCRYPTED(var)
 *
 * META_JSON is passed as AAD (Additional Authenticated Data) so that
 * header tampering is detected during decryption.
 *
 * The ENCRYPTED payload contains the serialized file data:
 *   For each entry: NAME_LEN(2) | NAME | DATA_LEN(4) | DATA
 * All concatenated, then compress7'd, then encrypted.
 */

import { compress7, decompress7 } from './compress7.js';
import { encryptAsync, decryptAsync } from './codec.js';
import { checksum, verify } from './integrity.js';
import {
  CRAFT_MAGIC,
  CRAFT_ARCHIVE_VERSION,
  SALT_LENGTH,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
} from './types.js';

// ── Types ─────────────────────────────────────────────────────────

/** A single file entry in the archive */
export interface ArchiveEntry {
  /** File name (path-like identifier) */
  name: string;
  /** MIME type of the file */
  mime: string;
  /** Raw file data */
  data: Buffer;
}

/** Result of an archive (pack) operation */
export interface ArchiveResult {
  /** The .craft archive buffer */
  buffer: Buffer;
  /** Number of entries packed */
  entryCount: number;
  /** Total original size in bytes (sum of all entry data) */
  totalOriginalSize: number;
  /** Size after compression (before encryption) */
  compressedSize: number;
  /** Compression ratio (0–1, lower is better) */
  compressionRatio: number;
  /** Space saved in bytes */
  spaceSaved: number;
  /** Space saved as percentage */
  spaceSavedPercent: number;
  /** Name of the winning compression strategy */
  strategyName: string;
  /** SHA-256 hex digest of all concatenated name+data pairs */
  checksum: string;
}

/** Result of an extract operation */
export interface ExtractResult {
  /** Extracted file entries */
  entries: ArchiveEntry[];
  /** Whether SHA-256 integrity verification passed */
  integrityVerified: boolean;
  /** Name of the compression strategy used */
  strategyName: string;
}

/** Shape of the metadata JSON stored in the archive header */
interface ArchiveMetadata {
  /** Per-entry metadata (name, mime, size — no data) */
  entries: Array<{ name: string; mime: string; size: number }>;
  /** SHA-256 checksum of all concatenated name+data pairs */
  checksum: string;
  /** Winning compression strategy name */
  compressionStrategy: string;
  /** Total original size of all entry data */
  totalSize: number;
}

// ── Helpers ───────────────────────────────────────────────────────

/**
 * Serialize entries into a flat binary buffer:
 *   For each entry: NAME_LEN(2) | NAME(utf8) | DATA_LEN(4) | DATA
 */
function serializeEntries(entries: ArchiveEntry[]): Buffer {
  const parts: Buffer[] = [];

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf-8');
    const nameLen = Buffer.alloc(2);
    nameLen.writeUInt16BE(nameBuf.length, 0);

    const dataLen = Buffer.alloc(4);
    dataLen.writeUInt32BE(entry.data.length, 0);

    parts.push(nameLen, nameBuf, dataLen, entry.data);
  }

  return Buffer.concat(parts);
}

/**
 * Deserialize a binary buffer back into entries.
 * Expects the format produced by serializeEntries.
 */
function deserializeEntries(data: Buffer): ArchiveEntry[] {
  const entries: ArchiveEntry[] = [];
  let offset = 0;

  while (offset < data.length) {
    // Read name
    if (offset + 2 > data.length) break;
    const nameLen = data.readUInt16BE(offset);
    offset += 2;

    if (offset + nameLen > data.length) break;
    const name = data.subarray(offset, offset + nameLen).toString('utf-8');
    offset += nameLen;

    // Read data
    if (offset + 4 > data.length) break;
    const dataLen = data.readUInt32BE(offset);
    offset += 4;

    if (offset + dataLen > data.length) break;
    const entryData = Buffer.from(data.subarray(offset, offset + dataLen));
    offset += dataLen;

    entries.push({ name, mime: '', data: entryData });
  }

  return entries;
}

/**
 * Compute a combined SHA-256 checksum over all name+data pairs.
 * This enables integrity verification without decrypting.
 */
function computeEntriesChecksum(entries: ArchiveEntry[]): string {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    parts.push(Buffer.from(entry.name, 'utf-8'), entry.data);
  }
  return checksum(Buffer.concat(parts));
}

// ── Validation ────────────────────────────────────────────────────

function validateEntries(entries: ArchiveEntry[]): void {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('Archive requires at least one entry. Provide a non-empty array of ArchiveEntry.');
  }
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry.name || typeof entry.name !== 'string' || entry.name.trim().length === 0) {
      throw new Error(`Entry at index ${i} must have a non-empty name.`);
    }
    if (!Buffer.isBuffer(entry.data) || entry.data.length === 0) {
      throw new Error(`Entry "${entry.name}" must have non-empty data (Buffer).`);
    }
  }
}

function validatePassphrase(passphrase: string): void {
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters for secure encryption.');
  }
}

// ── Public API ────────────────────────────────────────────────────

/**
 * Pack multiple files into a single encrypted `.craft` archive.
 *
 * Pipeline: checksum → serialize → compress7 → encrypt → package
 *
 * @param entries — Array of file entries to archive
 * @param passphrase — Encryption passphrase (min 8 characters)
 * @returns ArchiveResult with the archive buffer and operation stats
 */
export async function archive(
  entries: ArchiveEntry[],
  passphrase: string,
): Promise<ArchiveResult> {
  validateEntries(entries);
  validatePassphrase(passphrase);

  // Step 1: Compute integrity checksum over all name+data pairs
  const entriesChecksum = computeEntriesChecksum(entries);

  // Step 2: Serialize all entries into a flat binary block
  const serialized = serializeEntries(entries);

  // Step 3: Compress with the 7-fold adaptive engine
  const compressed = compress7(serialized);
  const totalOriginalSize = entries.reduce((sum, e) => sum + e.data.length, 0);

  // Step 4: Build plaintext metadata (stored unencrypted for peek)
  const meta: ArchiveMetadata = {
    entries: entries.map(e => ({ name: e.name, mime: e.mime, size: e.data.length })),
    checksum: entriesChecksum,
    compressionStrategy: compressed.strategyName,
    totalSize: totalOriginalSize,
  };
  const metaJson = Buffer.from(JSON.stringify(meta), 'utf-8');
  const metaLen = Buffer.alloc(4);
  metaLen.writeUInt32BE(metaJson.length, 0);

  // Step 5: AES-256-GCM encrypt. Metadata JSON is AAD for tamper detection.
  const { encrypted, iv, authTag, salt } = await encryptAsync(compressed.data, passphrase, metaJson);

  // Step 6: Assemble the .craft archive
  const buffer = Buffer.concat([
    CRAFT_MAGIC,
    Buffer.from([CRAFT_ARCHIVE_VERSION]),
    metaLen,
    metaJson,
    salt,
    iv,
    authTag,
    encrypted,
  ]);

  const compressionRatio = totalOriginalSize > 0 ? buffer.length / totalOriginalSize : 0;
  const spaceSaved = Math.max(0, totalOriginalSize - buffer.length);

  return {
    buffer,
    entryCount: entries.length,
    totalOriginalSize,
    compressedSize: compressed.data.length,
    compressionRatio,
    spaceSaved,
    spaceSavedPercent: totalOriginalSize > 0
      ? Math.max(0, (1 - compressionRatio) * 100)
      : 0,
    strategyName: compressed.strategyName,
    checksum: entriesChecksum,
  };
}

/**
 * Extract files from an encrypted `.craft` archive.
 *
 * Pipeline: parse header → decrypt → decompress7 → deserialize → verify
 *
 * @param craftBuffer — The .craft archive buffer
 * @param passphrase — Decryption passphrase
 * @returns ExtractResult with the file entries and verification status
 */
export async function extract(
  craftBuffer: Buffer,
  passphrase: string,
): Promise<ExtractResult> {
  if (!Buffer.isBuffer(craftBuffer) || craftBuffer.length < 20) {
    throw new Error(
      'Invalid CRAFT archive: buffer too small to contain a valid header. ' +
      'Minimum size is 20 bytes (magic + version + metadata + crypto params).'
    );
  }
  validatePassphrase(passphrase);

  let offset = 0;

  // Validate magic
  const magic = craftBuffer.subarray(offset, offset + 6);
  if (!magic.equals(CRAFT_MAGIC)) {
    throw new Error('Invalid CRAFT archive: magic bytes mismatch. This is not a valid .craft file.');
  }
  offset += 6;

  // Validate version
  const version = craftBuffer[offset];
  if (version !== CRAFT_ARCHIVE_VERSION) {
    throw new Error(
      `Unsupported CRAFT archive version: ${version}. Expected version ${CRAFT_ARCHIVE_VERSION} (multi-file).`
    );
  }
  offset += 1;

  // Read metadata
  if (offset + 4 > craftBuffer.length) {
    throw new Error('Invalid CRAFT archive: metadata length header exceeds buffer size.');
  }
  const metaLen = craftBuffer.readUInt32BE(offset);
  offset += 4;

  if (offset + metaLen > craftBuffer.length) {
    throw new Error('Invalid CRAFT archive: metadata section exceeds buffer size.');
  }
  const metaJson = craftBuffer.subarray(offset, offset + metaLen);
  const meta: ArchiveMetadata = JSON.parse(metaJson.toString('utf-8'));
  offset += metaLen;

  // Read crypto parameters
  if (offset + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH > craftBuffer.length) {
    throw new Error('Invalid CRAFT archive: crypto parameters exceed buffer size.');
  }
  const salt = craftBuffer.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;

  const iv = craftBuffer.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;

  const authTag = craftBuffer.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;

  const encrypted = craftBuffer.subarray(offset);

  // Decrypt with metadata as AAD
  const compressed = await decryptAsync(encrypted, passphrase, iv, authTag, salt, metaJson);

  // Decompress with the 7-fold engine
  const serialized = decompress7(compressed);

  // Deserialize entries
  const rawEntries = deserializeEntries(serialized);

  // Merge mime info from metadata back into entries
  const entries: ArchiveEntry[] = rawEntries.map((entry, i) => ({
    name: entry.name,
    mime: meta.entries[i]?.mime ?? 'application/octet-stream',
    data: entry.data,
  }));

  // Verify integrity: checksum of all name+data pairs
  const integrityVerified = verify(
    Buffer.concat(entries.flatMap(e => [Buffer.from(e.name, 'utf-8'), e.data])),
    meta.checksum,
  );

  return {
    entries,
    integrityVerified,
    strategyName: meta.compressionStrategy,
  };
}

/**
 * Peek at archive metadata without decrypting.
 *
 * Reads only the unencrypted header to return entry names,
 * entry count, and the integrity checksum. Useful for quick
 * inspection or UI display before full extraction.
 *
 * @param craftBuffer — The .craft archive buffer
 * @returns Entry count, entry names, and checksum
 */
export function peekArchiveMetadata(craftBuffer: Buffer): {
  entryCount: number;
  entryNames: string[];
  checksum: string;
} {
  if (!Buffer.isBuffer(craftBuffer) || craftBuffer.length < 11) {
    throw new Error('Invalid CRAFT archive: buffer too small to contain a valid header.');
  }

  let offset = 0;

  const magic = craftBuffer.subarray(offset, offset + 6);
  if (!magic.equals(CRAFT_MAGIC)) {
    throw new Error('Invalid CRAFT archive: magic bytes mismatch.');
  }
  offset += 6;

  const version = craftBuffer[offset];
  if (version !== CRAFT_ARCHIVE_VERSION) {
    throw new Error(
      `Not a CRAFT archive: version byte is ${version}, expected ${CRAFT_ARCHIVE_VERSION}. ` +
      'Use peekMetadata() for single-file packages.'
    );
  }
  offset += 1;

  const metaLen = craftBuffer.readUInt32BE(offset);
  offset += 4;

  if (offset + metaLen > craftBuffer.length) {
    throw new Error('Invalid CRAFT archive: metadata section exceeds buffer size.');
  }

  const meta: ArchiveMetadata = JSON.parse(
    craftBuffer.subarray(offset, offset + metaLen).toString('utf-8'),
  );

  return {
    entryCount: meta.entries.length,
    entryNames: meta.entries.map(e => e.name),
    checksum: meta.checksum,
  };
}
