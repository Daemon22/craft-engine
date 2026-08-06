import { compress, decompress } from '../src/index';
import { randomBytes } from 'crypto';

function roundtrips(data: Buffer): boolean {
  const c = compress(data);
  const d = decompress(c);
  return d.equals(data);
}

describe('craft-codec: deterministic fixtures', () => {
  test('empty buffer', () => {
    expect(roundtrips(Buffer.alloc(0))).toBe(true);
  });
  test('single byte, every possible value', () => {
    for (let b = 0; b < 256; b++) {
      expect(roundtrips(Buffer.from([b]))).toBe(true);
    }
  });
  test('two bytes, every combination of a sample grid', () => {
    for (let a = 0; a < 256; a += 17) {
      for (let b = 0; b < 256; b += 23) {
        expect(roundtrips(Buffer.from([a, b]))).toBe(true);
      }
    }
  });
  test('all-zero buffer, various sizes', () => {
    for (const sz of [1, 2, 3, 4, 5, 100, 1000, 70000]) {
      expect(roundtrips(Buffer.alloc(sz, 0))).toBe(true);
    }
  });
  test('all-0xFF buffer, various sizes', () => {
    for (const sz of [1, 2, 3, 4, 5, 100, 1000, 70000]) {
      expect(roundtrips(Buffer.alloc(sz, 0xff))).toBe(true);
    }
  });
  test('all 256 byte values in sequence, repeated', () => {
    const base = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    for (const reps of [1, 2, 10, 300]) {
      expect(roundtrips(Buffer.concat(Array(reps).fill(base)))).toBe(true);
    }
  });
  test('text data', () => {
    expect(roundtrips(Buffer.from('Hello, world! '.repeat(500)))).toBe(true);
    expect(roundtrips(Buffer.from('a'.repeat(100000)))).toBe(true);
  });
});

describe('craft-codec: fuzz — random data at many sizes', () => {
  test('uniform random bytes, many sizes, many trials', () => {
    const sizes = [1, 2, 3, 7, 16, 17, 100, 255, 256, 257, 1000, 4096, 65536, 200000];
    for (const sz of sizes) {
      for (let trial = 0; trial < 5; trial++) {
        const data = randomBytes(sz);
        expect(roundtrips(data)).toBe(true);
      }
    }
  });
});

describe('craft-codec: fuzz — skewed / adversarial distributions', () => {
  test('highly skewed byte distribution (mostly one value, rare others)', () => {
    for (let trial = 0; trial < 20; trial++) {
      const sz = 5000 + trial * 137;
      const data = Buffer.alloc(sz);
      const dominant = trial % 256;
      const rare = (trial * 7 + 1) % 256;
      for (let i = 0; i < sz; i++) {
        data[i] = i % 97 === 0 ? rare : dominant;
      }
      expect(roundtrips(data)).toBe(true);
    }
  });

  test('alternating two bytes (exercises context switching every symbol)', () => {
    for (let trial = 0; trial < 10; trial++) {
      const a = trial * 13 % 256;
      const b = (trial * 13 + 128) % 256;
      const sz = 3000 + trial * 91;
      const data = Buffer.alloc(sz);
      for (let i = 0; i < sz; i++) data[i] = i % 2 === 0 ? a : b;
      expect(roundtrips(data)).toBe(true);
    }
  });

  test('gradually increasing byte values (exercises rescale boundary repeatedly)', () => {
    const sz = 500000; // large enough to force many rescale cycles per context
    const data = Buffer.alloc(sz);
    for (let i = 0; i < sz; i++) data[i] = (i * 3 + Math.floor(i / 7)) & 0xff;
    expect(roundtrips(data)).toBe(true);
  });

  test('pseudo-random with strong Markov structure (context should help)', () => {
    // Each byte is a function of the previous byte, so an order-1 model
    // should predict it well — good test that model updates stay in sync
    // between encoder and decoder across many contexts.
    const sz = 200000;
    const data = Buffer.alloc(sz);
    let prev = 0;
    for (let i = 0; i < sz; i++) {
      prev = (prev * 37 + 11) & 0xff;
      data[i] = prev;
    }
    expect(roundtrips(data)).toBe(true);
  });

  test('many independent random trials at a fixed realistic size', () => {
    for (let trial = 0; trial < 50; trial++) {
      const data = randomBytes(2000 + trial);
      expect(roundtrips(data)).toBe(true);
    }
  });
});

describe('craft-codec: sanity on compression benefit', () => {
  test('actually compresses skewed/text data, not just round-trips it', () => {
    const data = Buffer.from('the quick brown fox '.repeat(2000));
    const c = compress(data);
    expect(c.length < data.length).toBe(true);
  });
});
