import { describe, expect, test } from 'vitest';
import { Readable, Writable } from 'node:stream';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { nano, macro, macroWithKeys, macroStream, craft, CraftTier } from '../src/lib/craft/index';
import type { NanoOptions } from '../src/lib/craft/index';
import { compress, deriveKeyAsync, encrypt } from '../src/lib/craft/codec';
import { checksum } from '../src/lib/craft/integrity';
import { CRAFT_MAGIC, CRAFT_VERSION, METADATA_LENGTH_MASK } from '../src/lib/craft/types';

const pass = 'metadata-auth-test-passphrase';
const content = Buffer.from('metadata authentication fixture');
const proOptions: NanoOptions = { tier: 'PRO' };
const govOptions: NanoOptions = { tier: 'GOV' };
// @ts-expect-error Unsupported tiers must be rejected by the public type.
const invalidOptions: NanoOptions = { tier: 'INVALID' };

function headerEnd(buf: Buffer): number {
  return 11 + (buf.readUInt32BE(7) & METADATA_LENGTH_MASK);
}

describe('single-file metadata authentication', () => {
  test('tier strings and the exported enum are accepted', () => {
    expect([proOptions.tier, govOptions.tier, CraftTier.FREE]).toEqual(['PRO', 'GOV', 'FREE']);
    expect(invalidOptions.tier).toBe('INVALID');
  });

  test.each([false, true])('v5 authenticates metadata and the flag (encrypted=%s)', async (encrypted) => {
    const pkg = await nano(content, 'safe.txt', 'text/plain', pass, { encryptMetadata: encrypted });
    expect(pkg.buffer[6]).toBe(CRAFT_VERSION);
    expect((await macro(pkg.buffer, pass)).buffer).toEqual(content);
    const end = headerEnd(pkg.buffer);
    const { key: dataKey } = await deriveKeyAsync(pass, pkg.buffer.subarray(end, end + 16));
    const metaKey = encrypted ? (await deriveKeyAsync(pass, pkg.buffer.subarray(11, 27))).key : undefined;
    expect((await macroWithKeys(pkg.buffer, { dataKey, metaKey })).buffer).toEqual(content);

    const altered = Buffer.from(pkg.buffer);
    if (encrypted) altered[11 + 44] ^= 1;
    else {
      const nameOffset = altered.indexOf(Buffer.from('safe.txt'), 11);
      expect(nameOffset).toBeGreaterThanOrEqual(11);
      altered[nameOffset] ^= 1;
    }
    await expect(macro(altered, pass)).rejects.toThrow();
    await expect(macroWithKeys(altered, { dataKey, metaKey })).rejects.toThrow();

    const flagChanged = Buffer.from(pkg.buffer);
    flagChanged[7] ^= 0x80;
    await expect(macro(flagChanged, pass)).rejects.toThrow();
    const downgraded = Buffer.from(pkg.buffer);
    downgraded[6] = 3;
    await expect(macro(downgraded, pass)).rejects.toThrow();
  });

  test('reads legacy v3 plaintext metadata and delegates v5 via macroStream', async () => {
    const compressed = compress(content);
    const metadata = Buffer.from(JSON.stringify({ originalName: 'legacy.txt', originalSize: content.length, originalMime: 'text/plain', compressedSize: compressed.length, compressionMode: 'brotli', encryptionAlgo: 'aes-256-gcm', originalChecksum: checksum(content), createdAt: '2026-01-01T00:00:00Z', version: 3, metadataEncrypted: false }));
    const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
    const payload = encrypt(compressed, pass);
    const legacy = Buffer.concat([CRAFT_MAGIC, Buffer.from([3]), length, metadata, payload.salt, payload.iv, payload.authTag, payload.encrypted]);
    expect((await macro(legacy, pass)).buffer).toEqual(content);
    const current = await nano(content, 'new.txt', 'text/plain', pass, { encryptMetadata: false });
    expect((await macroStream(current.buffer, pass)).buffer).toEqual(content);
    expect((await macroStream(Readable.from([current.buffer]), pass)).buffer).toEqual(content);
  });

  test('single-file output respects destinations, force and verifyOnly', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'craft-v5-output-'));
    try {
      const archive = (await nano(content, 'restore.txt', 'text/plain', pass)).buffer;
      const source = join(dir, 'input.craft');
      const dest = join(dir, 'restored.txt');
      writeFileSync(source, archive);
      const facadeDest = join(dir, 'facade.txt');
      await craft.unpack(source, pass, { output: facadeDest });
      expect(readFileSync(facadeDest)).toEqual(content);
      const result = await macroStream(source, pass, { output: dest });
      expect(result.buffer).toBeUndefined();
      expect(readFileSync(dest)).toEqual(content);
      writeFileSync(dest, 'existing');
      await expect(macroStream(archive, pass, { output: dest })).rejects.toThrow(/already exists/);
      expect(readFileSync(dest, 'utf8')).toBe('existing');
      await macroStream(Readable.from([archive]), pass, { output: dest, force: true });
      expect(readFileSync(dest)).toEqual(content);
      const verify = await macroStream(archive, pass, { output: dest, verifyOnly: true });
      expect(verify.buffer).toBeUndefined();
      expect(readFileSync(dest)).toEqual(content);
      const chunks: Buffer[] = [];
      const output = new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } });
      await macroStream(archive, pass, { output });
      expect(Buffer.concat(chunks)).toEqual(content);
      const failing = new Writable({ write(_chunk, _encoding, callback) { callback(new Error('write failed')); } });
      await expect(macroStream(archive, pass, { output: failing })).rejects.toThrow('write failed');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

});
