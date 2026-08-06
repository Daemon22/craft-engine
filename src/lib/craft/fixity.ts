/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/fixity — Passive bitrot / corruption detection
 * ═══════════════════════════════════════════════════════════════
 *
 *  Every other integrity check in this codebase happens at the moment
 *  of creation or restoration: nano() self-verifies right after building
 *  a package (see nano.ts), and macro() verifies the SHA-256 checksum +
 *  AES-GCM auth tag at decrypt time. Neither of those helps with a file
 *  that just sits on disk, untouched, for months or years — if a bit
 *  flips on the storage medium in the meantime, nobody finds out until
 *  someone tries to restore it, by which point the damage is already
 *  done and unrecoverable if it was the only copy.
 *
 *  Fixity checking (the standard term from digital preservation /
 *  archival practice) closes that gap: record a checksum of the package
 *  bytes at creation time, then periodically recompute and compare —
 *  without needing the encryption passphrase, so routine scans (cron
 *  jobs, backup verification, etc.) never need access to secrets. A
 *  mismatch means the package has changed since it was recorded — bit
 *  rot, filesystem corruption, or tampering — and should be restored
 *  from backup before it's needed.
 *
 *  This deliberately checks the *package* bytes (the ciphertext), not
 *  the original plaintext — that's what makes it passphrase-free. It
 *  can tell you "this file is no longer what it was," but not by itself
 *  decrypt it. For the strongest possible check (which also confirms
 *  the passphrase still works and the plaintext is recoverable), pair
 *  this with an occasional full macro() decrypt — see the CLI's
 *  `craft verify --deep`.
 */
import { createHash } from 'crypto';

export interface FixityRecord {
  /** Hash algorithm used to compute the digest, e.g. "sha256". */
  algorithm: 'sha256';
  /** SHA-256 hex digest of the .craft package bytes at record time. */
  sha256: string;
  /** Size in bytes of the package at record time. */
  size: number;
  /** ISO 8601 timestamp of when this record was made. */
  recordedAt: string;
  /** Format version, for forward compatibility of the record itself. */
  formatVersion: 1;
}

export interface FixityCheckResult {
  ok: boolean;
  expectedSha256: string;
  actualSha256: string;
  expectedSize: number;
  actualSize: number;
  /** Human-readable reason when ok is false. */
  reason?: string;
}

/** Compute a fixity record for a .craft package buffer. */
export function computeFixityRecord(packageBuffer: Buffer): FixityRecord {
  return {
    algorithm: 'sha256',
    sha256: createHash('sha256').update(packageBuffer).digest('hex'),
    size: packageBuffer.length,
    recordedAt: new Date().toISOString(),
    formatVersion: 1,
  };
}

/** Compare a package buffer's current state against a previously-recorded fixity record. */
export function verifyFixityRecord(packageBuffer: Buffer, record: FixityRecord): FixityCheckResult {
  const actualSha256 = createHash('sha256').update(packageBuffer).digest('hex');
  const actualSize = packageBuffer.length;
  const ok = actualSha256 === record.sha256 && actualSize === record.size;
  return {
    ok,
    expectedSha256: record.sha256,
    actualSha256,
    expectedSize: record.size,
    actualSize,
    reason: ok
      ? undefined
      : actualSize !== record.size
        ? `size changed: recorded ${record.size} bytes, now ${actualSize} bytes`
        : 'checksum mismatch: package bytes have changed since the fixity record was made',
  };
}

/** Serialize a fixity record to the sidecar file format (pretty JSON). */
export function serializeFixityRecord(record: FixityRecord): string {
  return JSON.stringify(record, null, 2) + '\n';
}

/** Parse a fixity record from sidecar file contents. Throws on malformed input. */
export function parseFixityRecord(text: string): FixityRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Fixity record is not valid JSON — the sidecar file may be corrupted or truncated.');
  }
  if (
    typeof parsed !== 'object' || parsed === null ||
    typeof (parsed as any).sha256 !== 'string' ||
    typeof (parsed as any).size !== 'number' ||
    typeof (parsed as any).recordedAt !== 'string'
  ) {
    throw new Error('Fixity record is missing required fields — the sidecar file may be corrupted or from an incompatible version.');
  }
  // Default `algorithm` for records written before the field existed, so
  // older sidecars still type-check and compare correctly.
  const record = (parsed as Record<string, unknown>);
  if (record.algorithm === undefined) record.algorithm = 'sha256';
  return record as unknown as FixityRecord;
}

/** Conventional sidecar filename for a given .craft package path. */
export function fixitySidecarPath(craftFilePath: string): string {
  return `${craftFilePath}.fixity.json`;
}
