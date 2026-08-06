/**
 * @craft/integrity — SHA-256 Checksum Verification
 *
 * Every CRAFT package carries a SHA-256 digest of the original data.
 * After Macro extraction, the restored data is verified against this
 * digest to confirm bit-perfect, lossless restoration.
 */

import { createHash } from 'crypto';

/**
 * Compute SHA-256 hex digest of a buffer.
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
 * @param data — The restored data to verify
 * @param expectedDigest — The expected SHA-256 hex digest
 * @returns true if data matches the expected digest
 */
export function verify(data: Buffer, expectedDigest: string): boolean {
  return checksum(data) === expectedDigest;
}
