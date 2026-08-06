/**
 * Fuzzing-style random input tests for craft-engine.
 *
 * These tests use randomized inputs to find edge cases that
 * carefully crafted tests might miss. They:
 * - Generate random data of various sizes and patterns
 * - Verify all operations produce correct results
 * - Test boundary conditions with random values
 * - Help catch regression bugs from code changes
 *
 * Using a fixed seed pattern for reproducibility while still
 * exercising diverse code paths.
 *
 * Note: Iteration counts are kept moderate to avoid excessive test times.
 */
import { describe, it, expect } from 'vitest';
import { nano, macro, peekMetadata } from '../src/lib/craft/index';
import { compress7, decompress7 } from '../src/lib/craft/compress7';
import { compress, decompress, encrypt, decrypt } from '../src/lib/craft/codec';
import { checksum, verify } from '../src/lib/craft/integrity';
import { computeFixityRecord, verifyFixityRecord } from '../src/lib/craft/fixity';
import { randomBytes } from 'crypto';

const PASS = 'fuzz-test-passphrase-123';

/**
 * Generate deterministic "random" data using a seed.
 * Same seed always produces same data for reproducibility.
 */
function seededRandom(seed: number, size: number): Buffer {
  const data = Buffer.alloc(size);
  let state = seed;
  for (let i = 0; i < size; i++) {
    // Simple LCG PRNG (not cryptographically secure, but deterministic)
    state = (state * 1664525 + 1013904223) & 0xFFFFFFFF;
    data[i] = (state >>> 16) & 0xFF;
  }
  return data;
}

/**
 * Generate various patterns of test data
 */
function generatePatternedData(pattern: string, size: number): Buffer {
  const data = Buffer.alloc(size);
  switch (pattern) {
    case 'random':
      return randomBytes(size);
    case 'sparse':
      data.fill(0);
      // Set ~1% of bytes to non-zero
      for (let i = 0; i < size; i += 97) {
        data[i] = (i * 7) & 0xFF;
      }
      return data;
    case 'blocky':
      // 64-byte repeating blocks with different fill values
      for (let i = 0; i < size; i++) {
        data[i] = Math.floor(i / 64) & 0xFF;
      }
      return data;
    case 'wave':
      // Sine-like wave pattern
      for (let i = 0; i < size; i++) {
        data[i] = Math.floor(128 + 127 * Math.sin(i / 10));
      }
      return data;
    case 'fractal':
      // Self-similar pattern at different scales
      for (let i = 0; i < size; i++) {
        let v = 0;
        for (let scale = 1; scale <= 64; scale *= 2) {
          v += ((i % (scale * 8)) < scale * 4) ? scale : 0;
        }
        data[i] = v & 0xFF;
      }
      return data;
    default:
      return seededRandom(pattern.charCodeAt(0) || 42, size);
  }
}

describe('fuzzing: nano/macro roundtrip with random data', () => {
  const sizes = [1, 7, 13, 64, 256, 1000, 4096];

  for (const size of sizes) {
    test(`seeded random roundtrip ${size}B`, () => {
      const data = seededRandom(size, size);
      const pkg = nano(data, `f${size}.bin`, 'application/octet-stream', PASS);
      const restored = macro(pkg.buffer, PASS);
      expect(restored.buffer).toEqual(data);
      expect(restored.integrityVerified).toBe(true);
    });
  }

  test('multiple different seeds produce valid packages', () => {
    for (let seed = 0; seed < 8; seed++) {
      const data = seededRandom(seed * 1337, 1000 + (seed * 137));
      const pkg = nano(data, `fuzz-${seed}.bin`, 'application/octet-stream', PASS);
      const restored = macro(pkg.buffer, PASS);
      expect(restored.buffer).toEqual(data);
    }
  });
});

describe('fuzzing: compress7 with various patterns', () => {
  const patterns = ['random', 'sparse', 'blocky', 'wave'];

  for (const pattern of patterns) {
    test(`compress7/decompress7 roundtrip ${pattern} 5KB`, () => {
      const data = generatePatternedData(pattern, 5000);
      const result = compress7(data);
      const restored = decompress7(result.data);
      expect(restored).toEqual(data);
    });
  }

  test('all strategies tested on random data', () => {
    const data = randomBytes(5000);
    const result = compress7(data);

    // Should have tried multiple strategies
    expect(result.allResults.length).toBeGreaterThan(1);

    // Final result must be valid
    expect(decompress7(result.data)).toEqual(data);
  });
});

describe('fuzzing: encryption with random data', () => {
  test('encrypt/decrypt roundtrip various sizes', () => {
    const sizes = [0, 1, 15, 255, 256, 257, 1023, 1024, 1025];
    for (const size of sizes) {
      const data = randomBytes(size);
      const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
      const decrypted = decrypt(encrypted, PASS, iv, authTag, salt);
      expect(decrypted.equals(data)).toBe(true);
    }
  });

  test('different passphrases with same data produce different outputs', () => {
    const data = randomBytes(500);
    const passphrases = Array.from({ length: 5 }, (_, i) =>
      `passphrase-variant-${i}-with-more-chars`
    );

    const results = passphrases.map(pass => encrypt(data, pass));

    // All encrypted outputs should be unique
    const ciphertexts = new Set(results.map(r => r.encrypted.toString('hex')));
    expect(ciphertexts.size).toBe(results.length);

    // Each should decrypt correctly with its own passphrase
    for (let i = 0; i < results.length; i++) {
      const { encrypted, iv, authTag, salt } = results[i];
      const decrypted = decrypt(encrypted, passphrases[i], iv, authTag, salt);
      expect(decrypted.equals(data)).toBe(true);
    }
  });
});

describe('fuzzing: integrity with random data', () => {
  test('checksum is unique for many random inputs', () => {
    const hashes = new Set<string>();
    const count = 30;

    for (let i = 0; i < count; i++) {
      const data = randomBytes(50 + (i * 17)); // Varying sizes
      const hash = checksum(data);
      hashes.add(hash);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }

    // With random data, we should get mostly unique hashes
    expect(hashes.size).toBeGreaterThan(count * 0.9); // At least 90% unique
  });

  test('fixity records detect corruption in random data', () => {
    for (let trial = 0; trial < 5; trial++) {
      const data = randomBytes(2000 + trial * 500);
      const record = computeFixityRecord(data);

      // Corrupt at random position
      const corrupted = Buffer.from(data);
      const corruptPos = (trial * 997) % corrupted.length;
      corrupted[corruptPos] ^= 0xFF;

      const result = verifyFixityRecord(corrupted, record);
      expect(result.ok).toBe(false);
    }
  });
});

describe('fuzzing: combined operations stress test', () => {
  test('nano then compress7 then encrypt chain', () => {
    const data = randomBytes(3000);

    // Chain multiple operations
    const pkg = nano(data, 'chain.bin', 'application/octet-stream', PASS);
    const compressed = compress7(pkg.buffer); // Compress the package
    const { encrypted, iv, authTag, salt } = encrypt(compressed.data, PASS);

    // Reverse the chain
    const decrypted = decrypt(encrypted, PASS, iv, authTag, salt);
    const decompressed = decompress7(decrypted);
    const restored = macro(decompressed, PASS);

    expect(restored.buffer).toEqual(data);
  });
});

describe('fuzzing: boundary value testing', () => {
  test('sizes around power-of-2 boundaries', () => {
    const boundaries = [
      1, 7, 8, 9,
      127, 128, 129,
      255, 256,
      511, 512,
      1023, 1024,
    ];

    for (const size of boundaries) {
      const data = seededRandom(size, size);
      const pkg = nano(data, `boundary${size}.bin`, 'application/octet-stream', PASS);
      const restored = macro(pkg.buffer, PASS);
      expect(restored.buffer.length).toBe(size);
      expect(restored.buffer).toEqual(data);
    }
  }, 60000); // 60s timeout for many nano/macro roundtrips

  test('filenames of various lengths around boundaries', () => {
    const lengths = [1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128];

    for (const len of lengths) {
      const name = 'a'.repeat(len);
      const data = Buffer.from(`filename-length-${len}`);
      const pkg = nano(data, `${name}.txt`, 'text/plain', PASS);
      const restored = macro(pkg.buffer, PASS);
      expect(restored.buffer).toEqual(data);
    }
  });
});

describe('fuzzing: adversarial inputs', () => {
  test('data designed to confuse LZ compression', () => {
    // Data that looks compressible but isn't (BWT-like worst case)
    const data = Buffer.alloc(5000);
    for (let i = 0; i < data.length; i++) {
      // Create long-range repetitions that are slightly off
      data[i] = (i * 127 + i % 256) & 0xFF;
    }
    const pkg = nano(data, 'adversarial-lz.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('data with embedded magic bytes', () => {
    // Try to confuse format detection with embedded CRAFT_MAGIC-like sequences
    const data = Buffer.concat([
      Buffer.from([0x43, 0x52, 0x41, 0x46, 0x54]), // Looks like "CRAFT"
      randomBytes(50),
      Buffer.from([0x03]), // Version byte
      randomBytes(100),
    ]);
    const pkg = nano(data, 'magic-embedded.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('data with high entropy followed by low entropy', () => {
    const data = Buffer.concat([
      randomBytes(2000), // High entropy
      Buffer.alloc(2000, 0x41), // Low entropy (all A's)
    ]);
    const pkg = nano(data, 'mixed-entropy.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });
});
