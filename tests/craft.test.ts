import { nano, macro, peekMetadata } from '../src/lib/index.js';
import { compress7, decompress7 } from '../src/lib/compress7.js';
import { compress, decompress, encrypt, decrypt, encryptAsync, decryptAsync } from '../src/lib/codec.js';
import { checksum, verify } from '../src/lib/integrity.js';

const PASS = 'correct-horse-battery';
const SHORT_PASS = 'short12'; // 7 chars, < 8

// ── Helpers ────────────────────────────────────────────────────

function makeBuffer(pattern: 'repeat' | 'sequential' | 'random' | 'zeros', size: number): Buffer {
  const buf = Buffer.allocUnsafe(size);
  if (pattern === 'repeat') for (let i = 0; i < size; i++) buf[i] = 0xAB;
  else if (pattern === 'sequential') for (let i = 0; i < size; i++) buf[i] = i & 0xFF;
  else if (pattern === 'zeros') buf.fill(0);
  else for (let i = 0; i < size; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf;
}

// ── Integrity ──────────────────────────────────────────────────

describe('integrity', () => {
  test('checksum produces 64-char hex', () => {
    const h = checksum(Buffer.from('hello'));
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  test('verify passes for matching data', () => {
    const data = Buffer.from('craft engine');
    expect(verify(data, checksum(data))).toBe(true);
  });

  test('verify fails for tampered data', () => {
    const data = Buffer.from('craft engine');
    const h = checksum(data);
    data[0] ^= 0xFF;
    expect(verify(data, h)).toBe(false);
  });
});

// ── Codec: compress/decompress (Brotli) ────────────────────────

describe('codec: brotli', () => {
  test('roundtrip small text', () => {
    const data = Buffer.from('The quick brown fox jumps over the lazy dog');
    expect(decompress(compress(data))).toEqual(data);
  });

  test('roundtrip 64KB random', () => {
    const data = makeBuffer('random', 64 * 1024);
    expect(decompress(compress(data))).toEqual(data);
  });
});

// ── Codec: encrypt/decrypt ─────────────────────────────────────

describe('codec: encrypt/decrypt (sync)', () => {
  test('roundtrip', () => {
    const data = Buffer.from('secret payload');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    expect(decrypt(encrypted, PASS, iv, authTag, salt)).toEqual(data);
  });

  test('wrong passphrase throws', () => {
    const data = Buffer.from('secret');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    expect(() => decrypt(encrypted, 'wrongpassphrase', iv, authTag, salt)).toThrow();
  });

  test('tampered ciphertext throws', () => {
    const data = Buffer.from('secret');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    encrypted[0] ^= 0xFF;
    expect(() => decrypt(encrypted, PASS, iv, authTag, salt)).toThrow();
  });

  test('AAD mismatch throws', () => {
    const data = Buffer.from('secret');
    const aad = Buffer.from('{"original":"metadata"}');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS, aad);
    expect(() => decrypt(encrypted, PASS, iv, authTag, salt, Buffer.from('tampered'))).toThrow();
  });

  test('unique salt per call', () => {
    const data = Buffer.from('same data');
    const r1 = encrypt(data, PASS);
    const r2 = encrypt(data, PASS);
    expect(r1.salt).not.toEqual(r2.salt);
    expect(r1.encrypted).not.toEqual(r2.encrypted);
  });
});

describe('codec: encrypt/decrypt (async)', () => {
  test('async roundtrip', async () => {
    const data = Buffer.from('async secret payload');
    const { encrypted, iv, authTag, salt } = await encryptAsync(data, PASS);
    expect(await decryptAsync(encrypted, PASS, iv, authTag, salt)).toEqual(data);
  });

  test('async with AAD roundtrip', async () => {
    const data = Buffer.from('async payload with aad');
    const aad = Buffer.from('metadata-aad');
    const { encrypted, iv, authTag, salt } = await encryptAsync(data, PASS, aad);
    expect(await decryptAsync(encrypted, PASS, iv, authTag, salt, aad)).toEqual(data);
  });
});

// ── compress7 / decompress7 ────────────────────────────────────

describe('compress7: all strategies', () => {
  const cases: Array<['repeat' | 'sequential' | 'random' | 'zeros', number]> = [
    ['repeat', 1024],
    ['sequential', 1024],
    ['random', 1024],
    ['zeros', 512],
    ['repeat', 64 * 1024],
    ['random', 64 * 1024],
  ];

  for (const [pattern, size] of cases) {
    test(`roundtrip ${pattern} ${size}B`, () => {
      const data = makeBuffer(pattern, size);
      const result = compress7(data);
      expect(result.data.length).toBeGreaterThan(0);
      expect(decompress7(result.data)).toEqual(data);
    });
  }

  test('picks winning strategy', () => {
    const data = makeBuffer('repeat', 4096);
    const result = compress7(data);
    expect(result.allResults.length).toBeGreaterThan(1);
    const winner = result.allResults.find(r => r.strategy === result.strategy)!;
    for (const r of result.allResults) {
      expect(winner.size).toBeLessThanOrEqual(r.size);
    }
  });

  test('throws on empty input', () => {
    expect(() => compress7(Buffer.alloc(0))).toThrow();
  });
});

// ── nano / macro roundtrips ────────────────────────────────────

describe('nano → macro roundtrip', () => {
  const fixtures = [
    { name: 'text', data: Buffer.from('Hello, Craft Engine!\n'.repeat(100)) },
    { name: 'json', data: Buffer.from(JSON.stringify({ key: 'value', nums: Array.from({ length: 100 }, (_, i) => i) })) },
    { name: 'binary sequential', data: makeBuffer('sequential', 2048) },
    { name: 'binary random', data: makeBuffer('random', 2048) },
    { name: 'large 256KB', data: makeBuffer('random', 256 * 1024) },
  ];

  for (const { name, data } of fixtures) {
    test(name, async () => {
      const pkg = await nano(data, `${name}.bin`, 'application/octet-stream', PASS);
      expect(pkg.buffer.length).toBeGreaterThan(0);
      expect(pkg.metadata.originalSize).toBe(data.length);

      const restored = await macro(pkg.buffer, PASS);
      expect(restored.buffer).toEqual(data);
      expect(restored.integrityVerified).toBe(true);
      expect(restored.metadata.originalName).toBe(`${name}.bin`);
    });
  }
});

// ── nano input validation ──────────────────────────────────────

describe('nano: input validation', () => {
  test('rejects empty data', async () => {
    await expect(nano(Buffer.alloc(0), 'f.bin', 'application/octet-stream', PASS)).rejects.toThrow();
  });

  test('rejects passphrase < 8 chars', async () => {
    await expect(nano(Buffer.from('data'), 'f.bin', 'application/octet-stream', SHORT_PASS)).rejects.toThrow();
  });

  test('rejects empty filename', async () => {
    await expect(nano(Buffer.from('data'), '', 'application/octet-stream', PASS)).rejects.toThrow();
  });
});

// ── macro: wrong passphrase ────────────────────────────────────

describe('macro: error handling', () => {
  test('wrong passphrase throws', async () => {
    const data = Buffer.from('secret data');
    const pkg = await nano(data, 'f.bin', 'application/octet-stream', PASS);
    await expect(macro(pkg.buffer, 'wrongpassphrase!')).rejects.toThrow();
  });

  test('corrupt package throws', async () => {
    const data = Buffer.from('secret data');
    const pkg = await nano(data, 'f.bin', 'application/octet-stream', PASS);
    const corrupt = Buffer.from(pkg.buffer);
    corrupt[corrupt.length - 10] ^= 0xFF;
    await expect(macro(corrupt, PASS)).rejects.toThrow();
  });

  test('rejects non-craft buffer', async () => {
    await expect(macro(Buffer.from('this is not a craft file'), PASS)).rejects.toThrow(/magic/i);
  });
});

// ── peekMetadata ───────────────────────────────────────────────

describe('peekMetadata', () => {
  test('reads metadata without passphrase', async () => {
    const data = Buffer.from('peek test');
    const pkg = await nano(data, 'peek.txt', 'text/plain', PASS);
    const meta = peekMetadata(pkg.buffer);
    expect(meta.originalName).toBe('peek.txt');
    expect(meta.originalMime).toBe('text/plain');
    expect(meta.originalSize).toBe(data.length);
    expect(meta.compressionMode).toBe('7fold');
  });

  test('rejects invalid buffer', () => {
    expect(() => peekMetadata(Buffer.from('garbage'))).toThrow();
  });
});

// ── passphrase isolation ───────────────────────────────────────

describe('passphrase isolation', () => {
  test('different passphrases produce different outputs', async () => {
    const data = Buffer.from('isolation test');
    const a = await nano(data, 'f.bin', 'application/octet-stream', 'passphrase-alpha');
    const b = await nano(data, 'f.bin', 'application/octet-stream', 'passphrase-bravo');
    expect(a.buffer).not.toEqual(b.buffer);
  });

  test('package created with A cannot be opened with B', async () => {
    const data = Buffer.from('isolation test');
    const pkg = await nano(data, 'f.bin', 'application/octet-stream', 'passphrase-alpha');
    await expect(macro(pkg.buffer, 'passphrase-bravo')).rejects.toThrow();
  });
});
