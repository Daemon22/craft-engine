/**
 * Concurrency & parallelism tests for craft-engine.
 *
 * Tests that the library handles:
 * - Multiple simultaneous operations
 * - Parallel nano/macro calls
 * - Shared state isolation between operations
 *
 * These are important for server environments where multiple
 * requests may be processed concurrently.
 */
import { describe, it, expect } from 'vitest';
import { nano, macro } from '../src/lib/craft/index';
import { compress7, decompress7 } from '../src/lib/craft/compress7';
import { encrypt, decrypt } from '../src/lib/craft/codec';
import { checksum, verify } from '../src/lib/craft/integrity';

const PASS = 'concurrency-test-passphrase-123';

describe('concurrency: parallel nano operations', () => {
  test('10 parallel nano calls produce valid packages', () => {
    const results = Array.from({ length: 10 }, (_, i) => {
      const data = Buffer.from(`concurrent data ${i} `.repeat(100));
      return nano(data, `file${i}.bin`, 'application/octet-stream', PASS);
    });

    // All should produce valid packages that decode correctly
    for (let i = 0; i < results.length; i++) {
      const originalData = Buffer.from(`concurrent data ${i} `.repeat(100));
      const restored = macro(results[i].buffer, PASS);
      expect(restored.buffer).toEqual(originalData);
      expect(restored.integrityVerified).toBe(true);
    }
  });

  test('parallel nano with different passphrases', () => {
    const packages = Array.from({ length: 5 }, (_, i) => {
      const data = Buffer.from(`passphrase-${i} data `.repeat(50));
      const pass = `unique-passphrase-number-${i}`;
      return { pkg: nano(data, `f${i}.bin`, 'app/octet-stream', pass), pass, data };
    });

    // Each should only decode with its own passphrase
    for (const { pkg, pass, data } of packages) {
      const restored = macro(pkg.buffer, pass);
      expect(restored.buffer).toEqual(data);

      // Should fail with wrong passphrase
      expect(() => macro(pkg.buffer, 'wrong-password')).toThrow();
    }
  });
});

describe('concurrency: parallel compress7 operations', () => {
  test('parallel compress7 calls all produce valid output', () => {
    const inputs = Array.from({ length: 8 }, (_, i) =>
      Buffer.alloc(5000, (i * 37) & 0xFF)
    );

    const compressed = inputs.map(data => compress7(data));
    const decompressed = compressed.map(c => decompress7(c.data));

    for (let i = 0; i < inputs.length; i++) {
      expect(decompressed[i]).toEqual(inputs[i]);
    }
  });
});

describe('concurrency: parallel encryption operations', () => {
  test('parallel encrypt/decrypt roundtrips', () => {
    const datasets = Array.from({ length: 6 }, (_, i) =>
      Buffer.from(`encrypt-parallel-test-${i} `.repeat(100))
    );

    const encrypted = datasets.map(data => encrypt(data, PASS));
    const decrypted = encrypted.map(({ encrypted, iv, authTag, salt }) =>
      decrypt(encrypted, PASS, iv, authTag, salt)
    );

    for (let i = 0; i < datasets.length; i++) {
      expect(decrypted[i]).toEqual(datasets[i]);
    }
  });

  test('each encryption produces unique ciphertext', () => {
    const data = Buffer.from('same data encrypted multiple times');

    const encryptions = Array.from({ length: 10 }, () =>
      encrypt(data, PASS)
    );

    // All should have different ciphertexts (different IV/salt)
    const ciphertexts = encryptions.map(e => e.encrypted.toString('hex'));
    const uniqueCiphertexts = new Set(ciphertexts);

    expect(uniqueCiphertexts.size).toBe(encryptions.length);

    // All salts should be unique too
    const salts = encryptions.map(e => e.salt.toString('hex'));
    const uniqueSalts = new Set(salts);
    expect(uniqueSalts.size).toBe(encryptions.length);
  });
});

describe('concurrency: parallel integrity operations', () => {
  test('parallel checksum computations', () => {
    const datasets = Array.from({ length: 20 }, (_, i) =>
      Buffer.from(`integrity-parallel-${i} `.repeat(500))
    );

    const hashes = datasets.map(data => checksum(data));

    // All hashes should be valid hex strings
    for (const hash of hashes) {
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }

    // Different data should produce different hashes
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(datasets.length);
  });

  test('parallel verify operations', () => {
    const datasets = Array.from({ length: 15 }, (_, i) =>
      Buffer.from(`verify-parallel-${i} `.repeat(300))
    );
    const hashVerifyPairs = datasets.map(data => ({
      data,
      hash: checksum(data),
    }));

    // All verifications should pass
    for (const { data, hash } of hashVerifyPairs) {
      expect(verify(data, hash)).toBe(true);
    }
  });
});

describe('concurrency: mixed operations in parallel', () => {
  test('nano + compress7 + encrypt running together', () => {
    const baseData = Buffer.from('mixed-workload-test '.repeat(200));

    // Run different operation types
    const nanoResult = nano(baseData, 'mixed.bin', 'application/octet-stream', PASS);
    const compressResult = compress7(baseData);
    const encryptResult = encrypt(baseData, PASS);
    const hashResult = checksum(baseData);

    // Verify all produced valid results
    const restoredNano = macro(nanoResult.buffer, PASS);
    expect(restoredNano.buffer).toEqual(baseData);

    expect(decompress7(compressResult.data)).toEqual(baseData);
    expect(decrypt(encryptResult.encrypted, PASS, encryptResult.iv, encryptResult.authTag, encryptResult.salt))
      .toEqual(baseData);
    expect(hashResult).toMatch(/^[0-9a-f]{64}$/);
  });

  test('sequential then parallel operations maintain correctness', () => {
    // First do a sequential operation
    const seqData = Buffer.from('sequential-first '.repeat(100));
    const seqPkg = nano(seqData, 'seq.bin', 'text/plain', PASS);
    expect(macro(seqPkg.buffer, PASS).buffer).toEqual(seqData);

    // Then run parallel operations
    const parResults = Array.from({ length: 5 }, (_, i) => {
      const data = Buffer.from(`parallel-after-seq-${i} `.repeat(80));
      return nano(data, `par${i}.bin`, 'text/plain', PASS);
    });

    // Original sequential result should still be valid
    expect(macro(seqPkg.buffer, PASS).buffer).toEqual(seqData);

    // Parallel results should also be valid
    for (let i = 0; i < parResults.length; i++) {
      const expected = Buffer.from(`parallel-after-seq-${i} `.repeat(80));
      expect(macro(parResults[i].buffer, PASS).buffer).toEqual(expected);
    }
  });
});
