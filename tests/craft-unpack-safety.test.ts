import { describe, expect, test } from 'vitest';
import { createReadStream, linkSync, mkdtempSync, openSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { once } from 'node:events';
import { craft, macroStream, nano, nanoStream } from '../src/lib/craft/index';
import { compress, encrypt } from '../src/lib/craft/codec';
import { checksum } from '../src/lib/craft/integrity';
import { CRAFT_MAGIC } from '../src/lib/craft/types';

const passphrase = 'archive-protection-passphrase';
const data = Buffer.from('protect the original archive');

function legacyArchive(): Buffer {
  const compressed = compress(data);
  const metadata = Buffer.from(JSON.stringify({ originalName: 'restore.txt', originalSize: data.length, originalMime: 'text/plain', compressedSize: compressed.length, compressionMode: 'brotli', encryptionAlgo: 'aes-256-gcm', originalChecksum: checksum(data), createdAt: '2026-01-01T00:00:00Z', version: 3, metadataEncrypted: false }));
  const length = Buffer.alloc(4); length.writeUInt32BE(metadata.length);
  const payload = encrypt(compressed, passphrase);
  return Buffer.concat([CRAFT_MAGIC, Buffer.from([3]), length, metadata, payload.salt, payload.iv, payload.authTag, payload.encrypted]);
}

describe('restore protects the source archive', () => {
  test.each(['v3', 'v5', 'v4'] as const)('%s refuses identical paths even with force', async (version) => {
    const dir = mkdtempSync(join(tmpdir(), 'craft-unpack-'));
    const source = join(dir, 'archive');
    try {
      if (version === 'v4') {
        await nanoStream(Readable.from([data]), 'file.txt', 'text/plain', passphrase, { output: source, verify: false });
      } else {
        writeFileSync(source, version === 'v3' ? legacyArchive() : (await nano(data, 'file.txt', 'text/plain', passphrase)).buffer);
      }
      const archive = readFileSync(source);
      await expect(craft.unpack(source, passphrase)).rejects.toThrow(/input archive/i);
      expect(readFileSync(source)).toEqual(archive);
      await expect(macroStream(source, passphrase, { output: `${dir}/./archive`, force: true })).rejects.toThrow(/input archive/i);
      expect(readFileSync(source)).toEqual(archive);
      const verified = await macroStream(source, passphrase, { output: source, force: true, verifyOnly: true });
      expect(verified.integrityVerified).toBe(true);
      expect(readFileSync(source)).toEqual(archive);
      const target = join(dir, 'restored');
      writeFileSync(target, 'older data');
      await macroStream(source, passphrase, { output: target, force: true });
      expect(readFileSync(target)).toEqual(data);
      expect(readFileSync(source)).toEqual(archive);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('refuses symlink and hardlink aliases, including ReadStream inputs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'craft-alias-'));
    try {
      const source = join(dir, 'input.craft');
      const alias = join(dir, 'alias');
      const hardlink = join(dir, 'hardlink');
      const archive = (await nano(data, 'file.txt', 'text/plain', passphrase)).buffer;
      writeFileSync(source, archive);
      symlinkSync(source, alias);
      linkSync(source, hardlink);
      await expect(macroStream(source, passphrase, { output: alias, force: true })).rejects.toThrow(/input archive/i);
      await expect(macroStream(source, passphrase, { output: hardlink, force: true })).rejects.toThrow(/input archive/i);
      const reader = createReadStream(source);
      await once(reader, 'open');
      try { await expect(macroStream(reader, passphrase, { output: source, force: true })).rejects.toThrow(/input archive/i); }
      finally { const closed = once(reader, 'close'); reader.destroy(); await closed; }
      const fd = openSync(source, 'r');
      const fdReader = createReadStream('', { fd });
      try { await expect(macroStream(fdReader, passphrase, { output: source, force: true })).rejects.toThrow(/input archive/i); }
      finally { const closed = once(fdReader, 'close'); fdReader.destroy(); await closed; }
      const distinct = join(dir, 'fd-output');
      writeFileSync(distinct, 'older data');
      const fd2 = openSync(source, 'r');
      const fdReader2 = createReadStream('', { fd: fd2 });
      await macroStream(fdReader2, passphrase, { output: distinct, force: true });
      expect(readFileSync(distinct)).toEqual(data);
      expect(readFileSync(source)).toEqual(archive);
      expect(readFileSync(alias)).toEqual(archive);
      expect(readFileSync(hardlink)).toEqual(archive);
      const restored = await craft.unpack(source, passphrase);
      expect(restored.path).toBe(join(dir, 'input'));
      expect(readFileSync(restored.path)).toEqual(data);
      expect(readFileSync(source)).toEqual(archive);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
