/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/integrity — SHA-256 Checksum Verification
 *  The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  The third fold of protection: integrity verification.
 *
 *  Every CRAFT package carries a SHA-256 digest of the original
 *  data. Upon Macro extraction, the restored data is verified
 *  against this digest to guarantee bit-perfect, lossless
 *  restoration. No data loss. No corruption. No compromise.
 *
 *  This is the "unified in diversity" principle made manifest:
 *  the checksum is the thread that binds the original and
 *  restored forms into one identity.
 */

import { createHash } from 'crypto';

/**
 * Compute SHA-256 hex digest of a buffer.
 *
 * This digest is embedded in the CRAFT package metadata and
 * verified after Macro extraction to ensure the restored data
 * is bit-identical to the original — guaranteed lossless.
 *
 * @param data — The data to checksum
 * @returns 64-character lowercase hex string
 */
export function checksum(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Verify that data matches an expected SHA-256 digest.
 *
 * Returns true only if the data is bit-identical to the original.
 * This is the final gate in the Macro pipeline — the moment of
 * truth where we confirm the craft was unwound perfectly.
 *
 * @param data — The restored data to verify
 * @param expectedDigest — The expected SHA-256 hex digest
 * @returns true if data matches the expected digest
 */
export function verify(data: Buffer, expectedDigest: string): boolean {
  return checksum(data) === expectedDigest;
}
