/**
 * Tests for the `@manya/craft-engine/lib/craft` subpath export
 * (src/lib/craft/*) — a separate, sync-API implementation from the
 * main `src/lib/index.ts` export covered by craft.test.ts.
 *
 * This file previously had zero test coverage, which is how the
 * metadata-encryption detection bug below went unnoticed: nano()/macro()
 * round-trips always passed on any single run, because the bug only
 * manifests when a random metadata salt happens to start with the byte
 * 0x7B ('{') — about 1 in 256 times. See the "metadata detection" block.
 */
import { nano, macro, peekMetadata } from '../src/lib/craft/index';
import { deriveKey, compress, encrypt } from '../src/lib/craft/codec';
import { compress7, decompress7 } from '../src/lib/craft/compress7';
import { checksum } from '../src/lib/craft/integrity';
import { CRAFT_MAGIC, CRAFT_VERSION } from '../src/lib/craft/types';
import { randomBytes, createCipheriv } from 'crypto';

const PASS = 'super-secret-passphrase-123';

describe('lib/craft: nano -> macro roundtrip (sync API)', () => {
  const fixtures = [
    { name: 'text', data: Buffer.from('Hello, Craft Engine!\n'.repeat(100)) },
    { name: 'all-256-byte-values', data: Buffer.concat(Array(20).fill(Buffer.from(Array.from({ length: 256 }, (_, i) => i)))) },
    { name: 'repeated-byte', data: Buffer.alloc(10_000, 0x41) },
  ];

  for (const { name, data } of fixtures) {
    test(name, () => {
      const pkg = nano(data, `${name}.bin`, 'application/octet-stream', PASS);
      const restored = macro(pkg.buffer, PASS);
      expect(restored.buffer).toEqual(data);
      expect(restored.integrityVerified).toBe(true);
    });
  }

  test('plaintext metadata mode roundtrips', () => {
    const data = Buffer.from('plaintext metadata test '.repeat(50));
    const pkg = nano(data, 'f.txt', 'text/plain', PASS, { encryptMetadata: false });
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('legacy brotli compression mode roundtrips', () => {
    const data = Buffer.from('legacy mode test data '.repeat(80));
    const pkg = nano(data, 'f.txt', 'text/plain', PASS, { compressionMode: 'brotli' });
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });
});

describe('lib/craft: metadata detection (regression)', () => {
  // Before the fix, encrypted-metadata detection sniffed the first
  // metadata byte for '{' (0x7B) to distinguish it from plaintext JSON.
  // Because encrypted metadata actually starts with a random salt byte,
  // roughly 1 in 256 packages had a salt starting with 0x7B and were
  // misidentified as plaintext, permanently failing to decrypt even with
  // the correct passphrase. This test forces that exact salt collision
  // to prove the current explicit-flag-based format (v3+) is immune.
  test('correctly decrypts when the metadata salt starts with 0x7B', () => {
    const data = Buffer.from('hello world '.repeat(30));
    const compressed = compress(data);
    const metadataJson = Buffer.from(JSON.stringify({
      originalName: 'secret.txt',
      originalSize: data.length,
      originalMime: 'text/plain',
      compressedSize: compressed.length,
      compressionMode: 'brotli',
      encryptionAlgo: 'aes-256-gcm',
      originalChecksum: checksum(data),
      createdAt: new Date().toISOString(),
      version: CRAFT_VERSION,
      metadataEncrypted: true,
    }), 'utf-8');

    // Force the exact collision byte that used to break decryption.
    const forcedMetaSalt = randomBytes(16);
    forcedMetaSalt[0] = 0x7b;

    const { key } = deriveKey(PASS, forcedMetaSalt);
    const metaIv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, metaIv);
    const encryptedMeta = Buffer.concat([cipher.update(metadataJson), cipher.final()]);
    const metaAuthTag = cipher.getAuthTag();

    const { encrypted, iv, authTag, salt } = encrypt(compressed, PASS);
    const metaSectionLength = 16 + 12 + 16 + encryptedMeta.length;
    const metadataLength = Buffer.alloc(4);
    // Mirrors what nano() writes: bit 31 set = encrypted metadata (v3+ format).
    metadataLength.writeUInt32BE(((metaSectionLength & 0x7fffffff) | 0x80000000) >>> 0, 0);

    const buffer = Buffer.concat([
      CRAFT_MAGIC, Buffer.from([CRAFT_VERSION]), metadataLength,
      forcedMetaSalt, metaIv, metaAuthTag, encryptedMeta,
      salt, iv, authTag, encrypted,
    ]);

    const result = macro(buffer, PASS);
    expect(result.buffer).toEqual(data);
    expect(result.metadata.originalName).toBe('secret.txt');
  });

  test('peekMetadata reports the correct version and redacts encrypted metadata', () => {
    const data = Buffer.from('peek test data '.repeat(20));
    const pkg = nano(data, 'secretname.txt', 'text/plain', PASS);
    const meta = peekMetadata(pkg.buffer);
    expect(meta.originalName).toBe('[encrypted]');
    expect(meta.version).toBe(CRAFT_VERSION);
  });

  test('still decodes a legacy v2 package (pre-flag format, no collision)', () => {
    // Simulates a package written before the v3 explicit-flag fix, using
    // the old header layout (no bit-31 flag) with a non-colliding salt.
    const data = Buffer.from('legacy v2 package data '.repeat(20));
    const compressed = compress(data);
    const metadataJson = Buffer.from(JSON.stringify({
      originalName: 'legacy.txt',
      originalSize: data.length,
      originalMime: 'text/plain',
      compressedSize: compressed.length,
      compressionMode: 'brotli',
      encryptionAlgo: 'aes-256-gcm',
      originalChecksum: checksum(data),
      createdAt: new Date().toISOString(),
      version: 2,
      metadataEncrypted: true,
    }), 'utf-8');

    let metaSalt = randomBytes(16);
    while (metaSalt[0] === 0x7b) metaSalt = randomBytes(16); // avoid the legacy collision on purpose

    const { key } = deriveKey(PASS, metaSalt);
    const metaIv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, metaIv);
    const encryptedMeta = Buffer.concat([cipher.update(metadataJson), cipher.final()]);
    const metaAuthTag = cipher.getAuthTag();

    const { encrypted, iv, authTag, salt } = encrypt(compressed, PASS);
    const metaSectionLength = 16 + 12 + 16 + encryptedMeta.length;
    const metadataLength = Buffer.alloc(4);
    metadataLength.writeUInt32BE(metaSectionLength, 0); // old format: no flag bit

    const buffer = Buffer.concat([
      CRAFT_MAGIC, Buffer.from([2]), metadataLength,
      metaSalt, metaIv, metaAuthTag, encryptedMeta,
      salt, iv, authTag, encrypted,
    ]);

    const result = macro(buffer, PASS);
    expect(result.buffer).toEqual(data);
    expect(result.metadata.originalName).toBe('legacy.txt');
  });
});

describe('lib/craft: error handling', () => {
  test('wrong passphrase throws', () => {
    const data = Buffer.from('secret data here');
    const pkg = nano(data, 'a.txt', 'text/plain', PASS);
    expect(() => macro(pkg.buffer, 'a-different-passphrase-99')).toThrow();
  });

  test('tampered ciphertext is rejected via the GCM auth tag', () => {
    const data = Buffer.from('important data to protect '.repeat(30));
    const pkg = nano(data, 'f.txt', 'text/plain', PASS);
    const tampered = Buffer.from(pkg.buffer);
    tampered[tampered.length - 5] ^= 0xff;
    expect(() => macro(tampered, PASS)).toThrow();
  });
});

describe('lib/craft: Zstd strategies (10, 11)', () => {
  // Zstd uses a different match-finder/entropy coder than Brotli, so it
  // wins on some inputs Brotli doesn't. This fixture is one of them —
  // it exercises the actual selection path (not just a forced strategy
  // byte), so it also proves decompress7 routes strategies 10/11 through
  // zstdDecompressSync instead of the Brotli path every other strategy uses.
  test('adaptive selection picks Zstd when it produces the smallest output', () => {
    const data = Buffer.from((
      'The quick brown fox jumps over the lazy dog. '.repeat(30) +
      'Pack my box with five dozen liquor jugs. '.repeat(30)
    ).repeat(10));

    const pkg = nano(data, 'f.txt', 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
    expect(pkg.metadata.compressionStrategyName).toContain('Zstd');
  });

  test('compress7/decompress7 round-trip across strategies 0-11 for varied inputs', () => {
    const samples = [
      Buffer.from(Array.from({ length: 5000 }, (_, i) => i % 256)), // delta-friendly
      Buffer.alloc(5000, 7), // constant
      require('crypto').randomBytes(3000), // incompressible
      Buffer.from('function foo(x) { return x + 1; }\n'.repeat(150)), // text
    ];
    for (const data of samples) {
      const c = compress7(data);
      const d = decompress7(c.data);
      expect(d).toEqual(data);
    }
  });
});

describe('lib/craft: Craft-Codec strategy (12, @manya/craft-codec)', () => {
  // Craft-Codec (order-1 adaptive context modeling) is meant to win on
  // data with strong local byte statistics but few long verbatim repeats
  // — exactly the case LZ-based Brotli/Zstd matching doesn't exploit
  // well. This fixture is engineered for that: each byte has a fixed
  // "preferred next byte" 70% of the time given the previous byte, and is
  // otherwise uniform random, so there's little for LZ matching to find.
  function order1FavorableFixture(size: number, seedOffset: number): Buffer {
    const data = Buffer.alloc(size);
    const preferred = new Uint8Array(256);
    for (let i = 0; i < 256; i++) preferred[i] = (i * 91 + 13 + seedOffset) & 0xff;
    let prev = 0;
    for (let i = 0; i < size; i++) {
      const b = Math.random() < 0.7 ? preferred[prev] : Math.floor(Math.random() * 256);
      data[i] = b;
      prev = b;
    }
    return data;
  }

  test('actually wins adaptive selection on data designed for it (not just present in the candidate list)', () => {
    const data = order1FavorableFixture(200_000, 0);
    const c = compress7(data);
    const d = decompress7(c.data);
    expect(d).toEqual(data);
    expect(c.strategy).toBe(12);
    // Should meaningfully beat the next-best generic strategy, not just tie.
    const others = c.allResults.filter(r => r.strategy !== 12).map(r => r.size);
    const bestOther = Math.min(...others);
    expect(c.compressedSize + 1 < bestOther).toBe(true);
  });

  test('still gets tried (and can win) even on the early-exit code path', () => {
    // Regression: an earlier version placed strategy 12 after the
    // early-exit return, so it was silently skipped whenever Brotli's
    // ratio alone looked "good enough" — exactly the kind of input this
    // fixture produces (Brotli achieves a moderate ratio here, well
    // under the early-exit threshold, but Craft-Codec still does better).
    let won = false;
    for (let trial = 0; trial < 8 && !won; trial++) {
      const data = order1FavorableFixture(200_000, trial * 7);
      const c = compress7(data);
      expect(decompress7(c.data)).toEqual(data);
      if (c.strategy === 12) won = true;
    }
    expect(won).toBe(true);
  });

  test('does not break selection or round-trip when it loses (e.g. on random data)', () => {
    const data = require('crypto').randomBytes(50_000);
    const c = compress7(data);
    const d = decompress7(c.data);
    expect(d).toEqual(data);
  });

  test('is skipped above its size cap but the package still round-trips correctly', () => {
    // Increased timeout: craft-codec (strategy 12) is O(256) per symbol and
    // gated to inputs <= 4MB, but we test slightly above that boundary to
    // verify the skip logic works. The large input + all 12 strategies needs
    // more than the default 5s timeout.
    const data = require('crypto').randomBytes(4 * 1024 * 1024 + 1000);
    const c = compress7(data);
    expect(c.strategy).not.toBe(12);
    expect(decompress7(c.data)).toEqual(data);
  }, 60000);
});
