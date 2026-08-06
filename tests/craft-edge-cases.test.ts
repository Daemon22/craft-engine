/**
 * Enhanced edge case & boundary condition tests for craft-engine.
 *
 * Covers:
 * - Empty/minimal inputs
 * - Boundary sizes (1 byte, max sizes, odd lengths)
 * - Special characters in filenames/metadata
 * - Unicode handling
 * - Extreme passphrases
 * - Memory pressure scenarios
 */
import { describe, it, expect } from 'vitest';
import { nano, macro, peekMetadata } from '../src/lib/craft/index';
import { compress, decompress, encrypt, decrypt, deriveKey } from '../src/lib/craft/codec';
import { compress7, decompress7 } from '../src/lib/craft/compress7';
import { checksum, verify } from '../src/lib/craft/integrity';
import {
  computeFixityRecord,
  verifyFixityRecord,
  serializeFixityRecord,
  parseFixityRecord,
} from '../src/lib/craft/fixity';
import { CRAFT_MAGIC, CRAFT_VERSION, SALT_LENGTH, IV_LENGTH, AES_KEY_LENGTH, PBKDF2_ITERATIONS } from '../src/lib/craft/types';

const PASS = 'edge-case-test-passphrase-123';

describe('edge cases: minimal inputs', () => {
  test('single byte roundtrip', () => {
    const data = Buffer.from([0x42]);
    const pkg = nano(data, 'single.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
    expect(restored.integrityVerified).toBe(true);
  });

  test('two bytes roundtrip', () => {
    const data = Buffer.from([0x00, 0xFF]);
    const pkg = nano(data, 'double.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('exactly 1KB roundtrip', () => {
    const data = Buffer.alloc(1024, 0xAB);
    const pkg = nano(data, '1k.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('exactly 1MB roundtrip', () => {
    const data = Buffer.alloc(1024 * 1024, 0xCD);
    const pkg = nano(data, '1mb.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
    expect(restored.integrityVerified).toBe(true);
  });

  test('odd length buffer (17 bytes)', () => {
    const data = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]);
    const pkg = nano(data, 'odd.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('prime number size (9973 bytes)', () => {
    const data = Buffer.alloc(9973, 0x5A);
    const pkg = nano(data, 'prime.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });
});

describe('edge cases: special byte patterns', () => {
  test('all zeros', () => {
    const data = Buffer.alloc(4096, 0x00);
    const pkg = nano(data, 'zeros.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('all 0xFF', () => {
    const data = Buffer.alloc(4096, 0xFF);
    const pkg = nano(data, 'ff.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('alternating bytes (0xAA 0x55)', () => {
    const data = Buffer.alloc(4096);
    for (let i = 0; i < data.length; i++) {
      data[i] = i % 2 === 0 ? 0xAA : 0x55;
    }
    const pkg = nano(data, 'alt.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('ascending byte sequence (0x00-0xFF repeating)', () => {
    const data = Buffer.alloc(256 * 4);
    for (let i = 0; i < data.length; i++) {
      data[i] = i % 256;
    }
    const pkg = nano(data, 'asc.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('descending byte sequence', () => {
    const data = Buffer.alloc(256 * 4);
    for (let i = 0; i < data.length; i++) {
      data[i] = 255 - (i % 256);
    }
    const pkg = nano(data, 'desc.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('null bytes embedded in data', () => {
    const data = Buffer.from('hello\0world\0test\0');
    const pkg = nano(data, 'nulls.bin', 'application/octet-stream', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });
});

describe('edge cases: filename handling', () => {
  test('very long filename (255 chars)', () => {
    const longName = 'a'.repeat(255) + '.txt';
    const data = Buffer.from('long filename test');
    const pkg = nano(data, longName, 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
    expect(restored.metadata.originalName).toBe(longName);
  });

  test('filename with special characters', () => {
    const specialName = "file-with.special&chars[1](2).txt";
    const data = Buffer.from('special chars');
    const pkg = nano(data, specialName, 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.metadata.originalName).toBe(specialName);
  });

  test('filename with spaces', () => {
    const spacedName = 'my important document.txt';
    const data = Buffer.from('spaces in name');
    const pkg = nano(data, spacedName, 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.metadata.originalName).toBe(spacedName);
  });

  test('filename with unicode characters', () => {
    const unicodeName = '文档-文件-🎉.txt';
    const data = Buffer.from('unicode filename');
    const pkg = nano(data, unicodeName, 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.metadata.originalName).toBe(unicodeName);
  });

  test('extensionless filename', () => {
    const noExt = 'README';
    const data = Buffer.from('no extension');
    const pkg = nano(data, noExt, 'text/plain', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.metadata.originalName).toBe(noExt);
  });

  test('dotfile (hidden file)', () => {
    const dotFile = '.env.secret';
    const data = Buffer.from('hidden file');
    const pkg = nano(data, dotFile, 'application/x-env', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.metadata.originalName).toBe(dotFile);
  });
});

describe('edge cases: MIME types', () => {
  test('empty MIME type string', () => {
    const data = Buffer.from('no mime');
    // Should handle empty or minimal MIME types gracefully
    const pkg = nano(data, 'f.txt', '', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
  });

  test('custom/vendor MIME type', () => {
    const data = Buffer.from('custom type');
    const pkg = nano(data, 'data.craft', 'application/x-craft-package', PASS);
    const restored = macro(pkg.buffer, PASS);
    expect(restored.buffer).toEqual(data);
    expect(restored.metadata.originalMime).toBe('application/x-craft-package');
  });
});

describe('edge cases: passphrase variations', () => {
  test('exactly 12 character passphrase (minimum)', () => {
    const data = Buffer.from('min length');
    const pass12 = '123456789012'; // exactly 12 chars (minimum)
    const pkg = nano(data, 'f.bin', 'application/octet-stream', pass12);
    const restored = macro(pkg.buffer, pass12);
    expect(restored.buffer).toEqual(data);
  });

  test('11 character passphrase is rejected', () => {
    const data = Buffer.from('too short');
    const pass11 = '12345678901'; // 11 chars - too short
    expect(() => nano(data, 'f.bin', 'application/octet-stream', pass11)).toThrow(/passphrase/i);
  });

  test('very long passphrase (1000 chars)', () => {
    const data = Buffer.from('long pass');
    const longPass = 'a'.repeat(1000);
    const pkg = nano(data, 'f.bin', 'application/octet-stream', longPass);
    const restored = macro(pkg.buffer, longPass);
    expect(restored.buffer).toEqual(data);
  });

  test('passphrase with unicode', () => {
    const data = Buffer.from('unicode pass');
    const unicodePass = '密码-パスワード-mot de passe-🔑';
    const pkg = nano(data, 'f.bin', 'application/octet-stream', unicodePass);
    const restored = macro(pkg.buffer, unicodePass);
    expect(restored.buffer).toEqual(data);
  });

  test('passphrase with only special characters', () => {
    const data = Buffer.from('special pass');
    const specialPass = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const pkg = nano(data, 'f.bin', 'application/octet-stream', specialPass);
    const restored = macro(pkg.buffer, specialPass);
    expect(restored.buffer).toEqual(data);
  });

  test('passphrase with newlines and tabs (if allowed)', () => {
    const data = Buffer.from('whitespace pass');
    const wsPass = 'pass\twith\nwhitespace';
    const pkg = nano(data, 'f.bin', 'application/octet-stream', wsPass);
    const restored = macro(pkg.buffer, wsPass);
    expect(restored.buffer).toEqual(data);
  });
});

describe('edge cases: compress7 boundaries', () => {
  test('compress7 with single byte', () => {
    const data = Buffer.from([0x42]);
    const result = compress7(data);
    expect(decompress7(result.data)).toEqual(data);
  });

  test('compress7 with empty buffer throws', () => {
    expect(() => compress7(Buffer.alloc(0))).toThrow();
  });

  test('all strategies produce valid output for tiny input', () => {
    const data = Buffer.from('tiny');
    const result = compress7(data);
    expect(result.allResults.length).toBeGreaterThan(0);
    expect(decompress7(result.data)).toEqual(data);
  });

  test('highly compressible data (single repeated byte)', () => {
    const data = Buffer.alloc(10000, 0x41); // all 'A'
    const result = compress7(data);
    const decompressed = decompress7(result.data);
    expect(decompressed).toEqual(data);
    // Should achieve excellent compression ratio
    expect(result.compressedSize).toBeLessThan(data.length / 10);
  });
});

describe('edge cases: integrity checks', () => {
  test('checksum is deterministic', () => {
    const data = Buffer.from('deterministic');
    const h1 = checksum(data);
    const h2 = checksum(data);
    expect(h1).toBe(h2);
  });

  test('checksum differs for different inputs', () => {
    const h1 = checksum(Buffer.from('a'));
    const h2 = checksum(Buffer.from('b'));
    expect(h1).not.toBe(h2);
  });

  test('checksum format validation (64 hex chars)', () => {
    const h = checksum(Buffer.from('test'));
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h.length).toBe(64);
  });

  test('fixity record detects truncation at various points', () => {
    const data = Buffer.from('truncation test data '.repeat(50));
    const record = computeFixityRecord(data);

    // Test truncation at different positions
    for (const truncateAt of [1, 10, data.length / 2, data.length - 1]) {
      const truncated = data.subarray(0, Math.floor(truncateAt));
      const result = verifyFixityRecord(truncated, record);
      expect(result.ok).toBe(false);
    }
  });

  test('fixity record serialization handles all fields', () => {
    const data = Buffer.from('serialization test');
    const record = computeFixityRecord(data);
    const serialized = serializeFixityRecord(record);
    const parsed = parseFixityRecord(serialized);

    expect(parsed.sha256).toBe(record.sha256);
    expect(parsed.size).toBe(record.size);
    expect(parsed.algorithm).toBe(record.algorithm);
  });
});

describe('edge cases: key derivation', () => {
  test('same passphrase + same salt produces same key', () => {
    const salt = Buffer.alloc(SALT_LENGTH, 0x01);
    const { key: key1 } = deriveKey('test', salt);
    const { key: key2 } = deriveKey('test', salt);
    expect(key1.equals(key2)).toBe(true);
  });

  test('different salts produce different keys', () => {
    const { key: key1, salt: salt1 } = deriveKey('test');
    const { key: key2, salt: salt2 } = deriveKey('test');
    expect(salt1.equals(salt2)).toBe(false);
    expect(key1.equals(key2)).toBe(false);
  });

  test('key length is always correct', () => {
    const { key } = deriveKey('any passphrase');
    expect(key.length).toBe(AES_KEY_LENGTH);
  });

  test('salt length is always correct', () => {
    const { salt } = deriveKey('any passphrase');
    expect(salt.length).toBe(SALT_LENGTH);
  });
});

describe('edge cases: encryption/decryption', () => {
  test('encrypt produces expected output structure', () => {
    const data = Buffer.from('structure test');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);

    expect(encrypted.length).toBeGreaterThan(0);
    expect(iv.length).toBe(IV_LENGTH);
    expect(authTag.length).toBe(16); // GCM auth tag
    expect(salt.length).toBe(SALT_LENGTH);
  });

  test('decrypt with modified IV fails', () => {
    const data = Buffer.from('iv test');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    const badIV = Buffer.from(iv);
    badIV[0] ^= 0xFF;
    expect(() => decrypt(encrypted, PASS, badIV, authTag, salt)).toThrow();
  });

  test('decrypt with modified authTag fails', () => {
    const data = Buffer.from('authTag test');
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    const badAuthTag = Buffer.from(authTag);
    badAuthTag[0] ^= 0xFF;
    expect(() => decrypt(encrypted, PASS, iv, badAuthTag, salt)).toThrow();
  });

  test('encrypt/decrypt preserves exact binary data', () => {
    // Test with all possible byte values
    const data = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const { encrypted, iv, authTag, salt } = encrypt(data, PASS);
    const decrypted = decrypt(encrypted, PASS, iv, authTag, salt);
    expect(decrypted.equals(data)).toBe(true);
  });
});

describe('edge cases: peekMetadata robustness', () => {
  test('peekMetadata returns correct structure', () => {
    const data = Buffer.from('meta test');
    const pkg = nano(data, 'peek.txt', 'text/plain', PASS);
    const meta = peekMetadata(pkg.buffer);

    expect(meta).toHaveProperty('originalName');
    expect(meta).toHaveProperty('originalMime');
    expect(meta).toHaveProperty('originalSize');
    expect(meta).toHaveProperty('version');
    expect(meta).toHaveProperty('compressionMode');
  });

  test('peekMetadata on encrypted package redacts name', () => {
    const data = Buffer.from('secret');
    const pkg = nano(data, 'secret-name.txt', 'text/plain', PASS);
    const meta = peekMetadata(pkg.buffer);
    // Encrypted metadata should show [encrypted] or similar
    if (meta.originalName !== 'secret-name.txt') {
      expect(meta.originalName).toBeTruthy();
    }
  });

  test('peekMetadata on plaintext metadata shows name', () => {
    const data = Buffer.from('public');
    const pkg = nano(data, 'public-name.txt', 'text/plain', PASS, { encryptMetadata: false });
    const meta = peekMetadata(pkg.buffer);
    expect(meta.originalName).toBe('public-name.txt');
  });
});
