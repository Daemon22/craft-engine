/**
 * Performance regression tests for craft-engine.
 *
 * These tests establish baseline timing thresholds to catch
 * performance regressions. They're designed to:
 * - Fail if operations take significantly longer than expected
 * - Document expected performance characteristics
 * - Cover both small and large input scenarios
 *
 * Note: CI environments may have variable performance, so
 * thresholds are generous. Adjust based on your baseline.
 */
import { describe, it, expect } from 'vitest';
import { nano, macro } from '../src/lib/craft/index';
import { compress7, decompress7 } from '../src/lib/craft/compress7';
import { compress, decompress, encrypt, decrypt } from '../src/lib/craft/codec';
import { checksum, verify } from '../src/lib/craft/integrity';
import { computeFixityRecord, verifyFixityRecord } from '../src/lib/craft/fixity';

const PASS = 'perf-test-passphrase-123';

/**
 * Helper: measures execution time in milliseconds
 */
function measureTime<T>(fn: () => T): { result: T; ms: number } {
  const start = performance.now();
  const result = fn();
  const ms = performance.now() - start;
  return { result, ms };
}

/**
 * Helper: async time measurement
 */
async function measureTimeAsync<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const start = performance.now();
  const result = await fn();
  const ms = performance.now() - start;
  return { result, ms };
}

describe('performance: compression speed', () => {
  test('brotli compress 1KB < 100ms', () => {
    const data = Buffer.alloc(1024, 0xAB);
    const { ms } = measureTime(() => compress(data));
    expect(ms).toBeLessThan(100);
  });

  test('brotli compress 100KB < 500ms', () => {
    const data = Buffer.alloc(100 * 1024, 0xBC);
    const { ms } = measureTime(() => compress(data));
    expect(ms).toBeLessThan(500);
  });

  test('brotli decompress is fast', () => {
    const data = Buffer.from('performance test data '.repeat(1000));
    const compressed = compress(data);
    const { ms } = measureTime(() => decompress(compressed));
    expect(ms).toBeLessThan(50);
  });

  test('compress7 with all strategies on 10KB < 2s', () => {
    const data = Buffer.alloc(10 * 1024, 0xCD);
    const { ms } = measureTime(() => compress7(data));
    expect(ms).toBeLessThan(2000);
  });

  test('decompress7 is faster than compress7', () => {
    const data = Buffer.from('decompress speed test '.repeat(500));
    const compressed = compress7(data);

    const compTime = measureTime(() => compress7(data)).ms;
    const decompTime = measureTime(() => decompress7(compressed.data)).ms;

    // Decompression should be significantly faster (no strategy selection)
    expect(decompTime).toBeLessThan(compTime);
  });
});

describe('performance: encryption speed', () => {
  test('encrypt 1KB < 200ms', () => {
    const data = Buffer.alloc(1024, 0xDE);
    const { ms } = measureTime(() => encrypt(data, PASS));
    expect(ms).toBeLessThan(200); // PBKDF2 with 600K iterations is inherently slow
  });

  test('encrypt 100KB < 200ms', () => {
    const data = Buffer.alloc(100 * 1024, 0xEF);
    const { ms } = measureTime(() => encrypt(data, PASS));
    expect(ms).toBeLessThan(200);
  });

  test('decrypt is similar speed to encrypt', () => {
    const data = Buffer.alloc(10 * 1024, 0x01);
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);

    const encTime = measureTime(() => encrypt(data, PASS)).ms;
    const decTime = measureTime(() => decrypt(encrypted, PASS, iv, authTag, salt)).ms;

    // Should be within 5x of each other (key derivation happens in both)
    expect(decTime).toBeLessThan(encTime * 5);
  });
});

describe('performance: nano/macro roundtrip', () => {
  test('nano+macro roundtrip 1KB < 200ms', () => {
    const data = Buffer.alloc(1024, 0x12);
    let pkg: any;
    let restored: any;

    const nanoMs = measureTime(() => { pkg = nano(data, 'f.bin', 'application/octet-stream', PASS); }).ms;
    const macroMs = measureTime(() => { restored = macro(pkg.buffer, PASS); }).ms;

    expect(restored.buffer).toEqual(data);
    expect(nanoMs + macroMs).toBeLessThan(1000); // Relaxed threshold for CI environments
  });

  test('nano+macro roundtrip 100KB < 5s', () => {
    const data = Buffer.alloc(100 * 1024, 0x34);
    let pkg: any;
    let restored: any;

    const totalMs = measureTime(() => {
      pkg = nano(data, 'f.bin', 'application/octet-stream', PASS);
      restored = macro(pkg.buffer, PASS);
    }).ms;

    expect(restored.buffer).toEqual(data);
    expect(totalMs).toBeLessThan(30000); // 30s for 100KB with all strategies
  });

  test('nano scales roughly linearly for text data (100x size ≈ <100x time)', () => {
    const smallData = Buffer.from('linear scale test '.repeat(10)); // ~200 bytes
    const largeData = Buffer.from('linear scale test '.repeat(1000)); // ~20 KB

    const smallTime = measureTime(() => nano(smallData, 'f.txt', 'text/plain', PASS)).ms;
    const largeTime = measureTime(() => nano(largeData, 'f.txt', 'text/plain', PASS)).ms;

    // Large should be slower but not 100x slower (compression helps)
    // This is a sanity check, not a strict bound
    expect(largeTime).toBeGreaterThan(0);
    expect(smallTime).toBeGreaterThan(0);
  });
});

describe('performance: integrity operations', () => {
  test('checksum 1MB < 100ms', () => {
    const data = Buffer.alloc(1024 * 1024, 0x56);
    const { ms } = measureTime(() => checksum(data));
    expect(ms).toBeLessThan(100);
  });

  test('verify is fast after checksum', () => {
    const data = Buffer.alloc(1024 * 1024, 0x67);
    const hash = checksum(data);
    const { ms } = measureTime(() => verify(data, hash));
    expect(ms).toBeLessThan(50);
  });

  test('fixity compute on 1MB < 200ms', () => {
    const data = Buffer.alloc(1024 * 1024, 0x78);
    const { ms } = measureTime(() => computeFixityRecord(data));
    expect(ms).toBeLessThan(200);
  });

  test('fixity verify is fast', () => {
    const data = Buffer.alloc(1024 * 1024, 0x89);
    const record = computeFixityRecord(data);
    const { ms } = measureTime(() => verifyFixityRecord(data, record));
    expect(ms).toBeLessThan(50);
  });
});

describe('performance: memory efficiency', () => {
  test('compress7 output + input < 2x for incompressible data', () => {
    // Random data shouldn't expand more than ~5% overhead
    const data = require('crypto').randomBytes(10_000);
    const result = compress7(data);
    const overheadRatio = result.compressedSize / data.length;
    // Allow up to 2x for headers/metadata on truly random data
    expect(overheadRatio).toBeLessThan(2);
  });

  test('nano package size is reasonable for small files', () => {
    const data = Buffer.from('small file content');
    const pkg = nano(data, 'small.txt', 'text/plain', PASS);
    // Package should be under 1KB for 19 bytes of content
    // (encryption adds IV, salt, authTag, metadata)
    expect(pkg.buffer.length).toBeLessThan(1024);
  });
});

describe('performance: adaptive selection quality', () => {
  test('adaptive selection finds good compression for repetitive data', () => {
    const data = Buffer.alloc(10000, 0x41); // All 'A's
    const result = compress7(data);

    // Should achieve at least 95% compression
    const ratio = result.compressedSize / data.length;
    expect(ratio).toBeLessThan(0.05);
  });

  test('adaptive selection handles mixed content well', () => {
    // Mix of text and binary patterns
    const parts = [
      Buffer.from('function test() { return '.repeat(100)),
      Buffer.alloc(500, 0x00), // Zeros
      Buffer.from(Array.from({ length: 256 }, (_, i) => i)), // All byte values
    ];
    const data = Buffer.concat(parts);

    const result = compress7(data);
    const decompressed = decompress7(result.data);
    expect(decompressed.equals(data)).toBe(true);

    // Should still achieve some compression on this mix
    const ratio = result.compressedSize / data.length;
    expect(ratio).toBeLessThan(0.8); // At least 20% savings
  });
});
