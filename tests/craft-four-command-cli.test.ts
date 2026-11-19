import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const cli = path.resolve(__dirname, '../bin/craft.js');
const tempDirs: string[] = [];

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'craft-four-command-'));
  tempDirs.push(dir);
  return dir;
}

function run(args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('four-command CLI compatibility router', () => {
  it('compresses and inflates a file without encrypting it', () => {
    const dir = tempDir();
    const source = path.join(dir, 'note.txt');
    const restored = path.join(dir, 'restored.txt');
    const bytes = Buffer.from('compression-only payload\n'.repeat(200));
    fs.writeFileSync(source, bytes);

    const packed = run(['nano', source]);
    expect(packed.status).toBe(0);
    expect(packed.stdout).toContain('compression only; not encrypted');
    const nanoPath = `${source}.nano`;
    expect(fs.readFileSync(nanoPath).subarray(0, 6).toString()).toBe('NANO02');

    const unpacked = run(['macro', nanoPath, '-o', restored]);
    expect(unpacked.status).toBe(0);
    expect(fs.readFileSync(restored).equals(bytes)).toBe(true);
  });

  it('refuses to overwrite compression output unless force is specified', () => {
    const dir = tempDir();
    const source = path.join(dir, 'note.txt');
    const archive = `${source}.nano`;
    fs.writeFileSync(source, 'source');
    fs.writeFileSync(archive, 'keep this file');

    const refused = run(['nano', source]);
    expect(refused.status).toBe(1);
    expect(fs.readFileSync(archive, 'utf8')).toBe('keep this file');

    const overwritten = run(['nano', source, '-f']);
    expect(overwritten.status).toBe(0);
    expect(fs.readFileSync(archive).subarray(0, 6).toString()).toBe('NANO02');
  });

  it('keeps production encryption and decryption available through craft/uncraft', () => {
    const dir = tempDir();
    const source = path.join(dir, 'secret.txt');
    const restored = path.join(dir, 'restored-secret.txt');
    const archive = path.join(dir, 'secret.craft');
    const bytes = Buffer.from('production-format compatibility payload');
    const passphrase = 'valid-passphrase-long-enough';
    fs.writeFileSync(source, bytes);

    const encrypted = run(['craft', source, '-p', passphrase, '-o', archive]);
    expect(encrypted.status, encrypted.stderr).toBe(0);
    expect(fs.existsSync(`${archive}.fixity.json`)).toBe(true);

    const decrypted = run(['uncraft', archive, '-p', passphrase, '-o', restored]);
    expect(decrypted.status, decrypted.stderr).toBe(0);
    expect(fs.readFileSync(restored).equals(bytes)).toBe(true);
  });

  it('keeps the old encrypted nano/macro command names as aliases', () => {
    const dir = tempDir();
    const source = path.join(dir, 'legacy.txt');
    const restored = path.join(dir, 'legacy-restored.txt');
    const archive = path.join(dir, 'legacy.craft');
    const bytes = Buffer.from('legacy CLI behavior remains available');
    const passphrase = 'valid-passphrase-long-enough';
    fs.writeFileSync(source, bytes);

    const encrypted = run(['legacy-nano', source, '-p', passphrase, '-o', archive]);
    expect(encrypted.status, encrypted.stderr).toBe(0);
    const decrypted = run(['legacy-macro', archive, '-p', passphrase, '-o', restored]);
    expect(decrypted.status, decrypted.stderr).toBe(0);
    expect(fs.readFileSync(restored).equals(bytes)).toBe(true);
  });
});
