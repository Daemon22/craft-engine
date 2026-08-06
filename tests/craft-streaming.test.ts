/**
 * Regression + validation tests for the v4 streaming path (nanoStream /
 * macroStream). These run alongside the existing v1–v3 suite and MUST NOT
 * change it — they only ADD coverage for the second execution path.
 *
 * Validation contract (against the gold-standard nano()/macro()):
 *  - restored bytes are bit-identical to the original, and identical between the
 *    v1–v3 path (`macro(nano(x))`) and the v4 path (`macroStream(nanoStream(x))`);
 *  - SHA-256 of the restored data equals `metadata.originalChecksum` and equals
 *    `checksum(original)`;
 *  - both paths detect a 1-byte flip (AES-GCM tag) and a wrong passphrase;
 *  - macroStream reads v1–v3 archives unchanged (delegates to macro()).
 *
 * Run: npx vitest run tests/craft-streaming.test.ts
 */
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Readable } from 'stream';
import { randomBytes, createHash } from 'crypto';
import { nano, macro } from '../src/lib/craft/index';
import { nanoStream, macroStream, peekStreamMetadata } from '../src/lib/craft/index';
import { STREAM_VERSION } from '../src/lib/craft/streamCore';

const PASS = 'correct-horse-battery-staple';

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function bufToStream(buf: Buffer): NodeJS.ReadableStream {
  // Emit the buffer in 7 KiB pieces so the chunker is exercised.
  const pieces: Buffer[] = [];
  for (let i = 0; i < buf.length; i += 7 * 1024) pieces.push(buf.subarray(i, i + 7 * 1024));
  return Readable.from(pieces.length ? pieces : [Buffer.alloc(0)]);
}

let tmpDir: string;
beforeAll(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'craft-stream-test-')); });
afterAll(() => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ } });

function tmpFile(name: string): string { return path.join(tmpDir, `${name}-${randomBytes(4).toString('hex')}.craft`); }
function inputPath(name: string, buf: Buffer): string {
  const p = path.join(tmpDir, `in-${name}-${randomBytes(4).toString('hex')}`);
  fs.writeFileSync(p, buf);
  return p;
}

const fixtures = {
  text: Buffer.from('Hello, CRAFT streaming engine!\n'.repeat(4_000)), // ~92 KB
  json: Buffer.from(JSON.stringify({
    items: Array.from({ length: 500 }, (_, i) => ({ id: i, name: `item-${i}`, tags: ['a', 'b', 'c'] })),
    nested: { a: 1, b: 2, c: [1, 2, 3] },
  })),
  repeated: Buffer.alloc(256 * 1024, 0x41), // 256 KB of 'A'
  structured: Buffer.concat(Array.from({ length: 2048 }, () => Buffer.from(Array.from({ length: 256 }, (_, i) => (i + 7) % 256)))),
  random: randomBytes(512 * 1024), // 512 KB incompressible
  allBytes: Buffer.concat(Array.from({ length: 4096 }, () => Buffer.from(Array.from({ length: 256 }, (_, i) => i)))),
  tiny: Buffer.from('{"tiny":true}'),
};

describe('nanoStream / macroStream (v4 chunked streaming)', () => {
  for (const [name, data] of Object.entries(fixtures)) {
    test(`restores bit-identical to original (${name}, ${data.length} B)`, async () => {
      const out = tmpFile(name);
      const res = await nanoStream(bufToStream(data), `${name}.bin`, 'application/octet-stream', PASS, { output: out, chunkSize: 4096 });

      // archive is v4
      const ver = fs.readFileSync(out)[6];
      expect(ver).toBe(STREAM_VERSION);
      expect(res.integrityVerified).toBe(true);
      expect(res.bytesProcessed).toBe(data.length);
      expect(res.chunksProcessed).toBeGreaterThan(0);

      // stream-decode round-trip
      const restored = await macroStream(out, PASS);
      expect(restored.integrityVerified).toBe(true);
      expect(restored.buffer).toBeDefined();
      expect(restored.bytesRestored).toBe(data.length);
      expect((restored.buffer as Buffer).equals(data)).toBe(true);
      // SHA-256 matches original and the metadata checksum
      expect(sha256(restored.buffer as Buffer)).toBe(sha256(data));
      expect(sha256(restored.buffer as Buffer)).toBe(restored.metadata.originalChecksum);
    });

    test(`identical restored bytes vs gold-standard nano()/macro() (${name})`, async () => {
      const pkg = await nano(data, `${name}.bin`, 'application/octet-stream', PASS);
      const goldRestored = await macro(pkg.buffer, PASS);
      expect(goldRestored.integrityVerified).toBe(true);
      expect(goldRestored.buffer.equals(data)).toBe(true);

      const out = tmpFile(`${name}-gold`);
      await nanoStream(bufToStream(data), `${name}.bin`, 'application/octet-stream', PASS, { output: out, chunkSize: 8192, verify: false });

      // The two archives differ byte-for-byte (different strategies/versions),
      // but the RESTORED bytes must be identical, and the SHA-256 of the
      // restored output must match.
      const v4pkg = fs.readFileSync(out);
      expect(v4pkg[6]).toBe(STREAM_VERSION);
      expect(v4pkg.equals(pkg.buffer)).toBe(false);

      const restored = await macroStream(out, PASS);
      expect(restored.buffer).toBeDefined();
      expect((restored.buffer as Buffer).equals(goldRestored.buffer)).toBe(true);
      expect(sha256(restored.buffer as Buffer)).toBe(sha256(goldRestored.buffer));
    });
  }

  test('macroStream reads v1-v3 archives (universal reader) by delegating to macro()', async () => {
    const data = fixtures.text;
    const pkg = await nano(data, 'text.bin', 'text/plain', PASS); // v3
    const restored = await macroStream(pkg.buffer, PASS);
    expect(restored.integrityVerified).toBe(true);
    expect((restored.buffer as Buffer).equals(data)).toBe(true);
    expect(restored.chunksRead).toBe(0); // v1-v3 path doesn't chunk
  });

  test('macroStream reads v4 archives passed as an in-memory Buffer', async () => {
    const data = fixtures.random;
    const out = tmpFile('buf-in');
    await nanoStream(bufToStream(data), 'random.bin', 'application/octet-stream', PASS, { output: out });
    const buf = fs.readFileSync(out);
    const restored = await macroStream(buf, PASS);
    expect(restored.integrityVerified).toBe(true);
    expect((restored.buffer as Buffer).equals(data)).toBe(true);
  });

  test('macroStream streams to an output file (constant-memory path)', async () => {
    const data = fixtures.structured;
    const pkg = tmpFile('stream-out');
    await nanoStream(bufToStream(data), 'structured.bin', 'application/octet-stream', PASS, { output: pkg, chunkSize: 4096 });
    const restoredPath = pkg + '.restored';
    const res = await macroStream(pkg, PASS, { output: restoredPath });
    expect(res.integrityVerified).toBe(true);
    expect(res.buffer).toBeUndefined(); // not collected when streaming to a file
    expect(fs.readFileSync(restoredPath).equals(data)).toBe(true);
  });

  test('verifyOnly decodes + verifies without emitting output', async () => {
    const data = fixtures.json;
    const out = tmpFile('verify');
    await nanoStream(bufToStream(data), 'data.json', 'application/json', PASS, { output: out });
    const res = await macroStream(out, PASS, { verifyOnly: true });
    expect(res.buffer).toBeUndefined();
    expect(res.integrityVerified).toBe(true);
    expect(res.bytesRestored).toBe(data.length);
    expect(res.chunksRead).toBeGreaterThan(0);
  });

  test('peekStreamMetadata surfaces public fields without a passphrase', async () => {
    const data = fixtures.text;
    const out = tmpFile('peek');
    await nanoStream(bufToStream(data), 'text.bin', 'text/plain', PASS, { output: out, verify: false, chunkSize: 4096 });
    const meta = await peekStreamMetadata(fs.readFileSync(out));
    expect(meta.version).toBe(STREAM_VERSION);
    expect(meta.originalSize).toBe(data.length);
    expect(meta.chunkCount).toBeGreaterThan(0);
    expect(meta.chunkSize).toBe(4096);
    expect(meta.compressionMode).toBe('stream');
    // Sensitive fields are redacted without a passphrase.
    expect(meta.originalName).toBe('[encrypted]');
    expect(meta.originalChecksum).toBe('[encrypted]');

    // With the passphrase, the full metadata is decryptable.
    const full = await peekStreamMetadata(fs.readFileSync(out), PASS);
    expect(full.originalName).toBe('text.bin');
    expect(full.originalMime).toBe('text/plain');
    expect(full.originalChecksum).toBe(sha256(data));
    expect(full.originalSize).toBe(data.length);
  });
});

describe('v4 streaming security & corruption detection', () => {
  test('1-byte ciphertext flip is detected (per-chunk AES-GCM tag)', async () => {
    const data = fixtures.random;
    const out = tmpFile('tamper');
    await nanoStream(bufToStream(data), 'random.bin', 'application/octet-stream', PASS, { output: out, chunkSize: 4096 });
    const buf = fs.readFileSync(out);

    // Flip a byte well inside the first chunk's ciphertext region (past header).
    // Header ≈ 11 + (44 + encMeta) + 16 + 4 + 4 + 8 ≈ 83 + encMeta; pick a safe offset.
    let off = buf.length - 1;
    while (off > 200 && buf[off] === 0) off--;
    buf[off] ^= 0xff;
    await expect(macroStream(Buffer.from(buf), PASS)).rejects.toThrow(/Integrity failure|auth tag|checksum mismatch/i);
  });

  test('wrong passphrase is rejected (metadata AES-GCM tag)', async () => {
    const data = fixtures.tiny;
    const out = tmpFile('wrongpp');
    await nanoStream(bufToStream(data), 'tiny.bin', 'application/octet-stream', PASS, { output: out, verify: false });
    await expect(macroStream(out, 'a-different-pass-12', { verifyOnly: true })).rejects.toThrow(/passphrase/i);
  });

  test('wrong passphrase on a v1-v3 archive still delegates correctly', async () => {
    const data = fixtures.tiny;
    const pkg = await nano(data, 'tiny.bin', 'application/octet-stream', PASS);
    await expect(macroStream(pkg.buffer, 'wrong-passphrase-12')).rejects.toThrow(/passphrase/i);
  });

  test('atomic publish refuses to overwrite without --force (API)', async () => {
    const data = fixtures.tiny;
    const out = tmpFile('overwrite');
    await nanoStream(bufToStream(data), 'tiny.bin', 'application/octet-stream', PASS, { output: out, verify: false });
    // A second write to the SAME path must refuse (mirrors safeWriteFile).
    await expect(
      nanoStream(bufToStream(data), 'tiny.bin', 'application/octet-stream', PASS, { output: out, verify: false }),
    ).rejects.toThrow(/already exists/);

    // With force=true it succeeds.
    await nanoStream(bufToStream(data), 'tiny.bin', 'application/octet-stream', PASS, { output: out, verify: false, force: true });
    expect(fs.readFileSync(out)[6]).toBe(STREAM_VERSION);
  });

  test('configurable chunk size round-trips identically', async () => {
    const data = fixtures.random; // incompressible → chunk count is meaningful
    for (const chunkSize of [512, 4096, 65536, 256 * 1024]) {
      const out = tmpFile(`cs-${chunkSize}`);
      const res = await nanoStream(bufToStream(data), 'random.bin', 'application/octet-stream', PASS, { output: out, chunkSize, verify: false });
      const expectedChunks = Math.ceil(data.length / chunkSize);
      expect(res.chunksProcessed).toBe(expectedChunks);
      const restored = await macroStream(out, PASS);
      expect(restored.integrityVerified).toBe(true);
      expect((restored.buffer as Buffer).equals(data)).toBe(true);
    }
  });

  test('zstd strategy round-trips and matches SHA-256', async () => {
    const data = fixtures.structured;
    const out = tmpFile('zstd');
    await nanoStream(bufToStream(data), 's.bin', 'application/octet-stream', PASS, {
      output: out,
      compressionStrategy: 'zstd',
      level: 19,
      chunkSize: 8192,
    });
    const meta = await peekStreamMetadata(fs.readFileSync(out), PASS);
    expect(meta.compressionStrategyKey).toBe('zstd');
    const restored = await macroStream(out, PASS);
    expect(restored.integrityVerified).toBe(true);
    expect(sha256(restored.buffer as Buffer)).toBe(sha256(data));
  });

  test('brotli strategy round-trips and matches SHA-256', async () => {
    const data = fixtures.text;
    const out = tmpFile('brotli');
    await nanoStream(bufToStream(data), 't.txt', 'text/plain', PASS, {
      output: out,
      compressionStrategy: 'brotli',
      quality: 9,
      chunkSize: 4096,
      verify: false,
    });
    const meta = await peekStreamMetadata(fs.readFileSync(out), PASS);
    expect(meta.compressionStrategyKey).toBe('brotli');
    const restored = await macroStream(out, PASS);
    expect(restored.integrityVerified).toBe(true);
    expect((restored.buffer as Buffer).equals(data)).toBe(true);
  });
});
