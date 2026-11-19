import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CRAFT_ARTIFACT_ICONS, getCraftArtifactIcon, getCraftArtifactIconForFile } from '../src/lib/craft/artifact-icons';

describe('artifact icon mapping', () => {
  it('preserves and resolves each user-supplied source filename', () => {
    const sourceDirectory = path.resolve(process.cwd(), 'assets/craft-icons/source');
    const expected = [
      CRAFT_ARTIFACT_ICONS.compressionOnly.sourceFilename,
      CRAFT_ARTIFACT_ICONS.encryptionOnly.sourceFilename,
      CRAFT_ARTIFACT_ICONS.compressionAndEncryption.sourceFilename,
    ];
    expect(expected).toEqual([
      'Compressed_Only.png',
      'Encrypted_Only.png',
      'Compressed & Encrypted.png',
    ]);
    for (const filename of expected) {
      expect(fs.statSync(path.join(sourceDirectory, filename)).isFile()).toBe(true);
    }
  });

  it('maps supported output extensions to their matching public icons', () => {
    for (const artifact of [
      CRAFT_ARTIFACT_ICONS.compressionOnly,
      CRAFT_ARTIFACT_ICONS.encryptionOnly,
      CRAFT_ARTIFACT_ICONS.compressionAndEncryption,
    ]) {
      expect(fs.existsSync(path.join(process.cwd(), 'public', artifact.publicPath))).toBe(true);
    }

    expect(CRAFT_ARTIFACT_ICONS.compressionOnly.extension).toBe('.nano');
    expect(CRAFT_ARTIFACT_ICONS.compressionAndEncryption.extension).toBe('.craft');
    expect(CRAFT_ARTIFACT_ICONS.encryptionOnly.extension).toBeNull();
    expect(CRAFT_ARTIFACT_ICONS.encryptionOnly.supported).toBe(false);
    expect(getCraftArtifactIcon('compression-only')).toEqual(CRAFT_ARTIFACT_ICONS.compressionOnly);
    expect(getCraftArtifactIcon('compression-and-encryption')).toEqual(CRAFT_ARTIFACT_ICONS.compressionAndEncryption);
  });

  it('maps `.nano` files to the compression-only icon', () => {
    expect(getCraftArtifactIconForFile('report.nano')).toEqual(CRAFT_ARTIFACT_ICONS.compressionOnly);
    expect(getCraftArtifactIconForFile('/archive/quarterly-report.nano')?.publicPath).toBe(
      '/craft-icons/compressed-only.webp',
    );
    expect(getCraftArtifactIconForFile('REPORT.NANO')?.kind).toBe('compression-only');
  });

  it('maps `.craft` files to the compression-and-encryption icon', () => {
    expect(getCraftArtifactIconForFile('database-backup.craft')).toEqual(
      CRAFT_ARTIFACT_ICONS.compressionAndEncryption,
    );
    expect(getCraftArtifactIconForFile('C:\\vault\\nightly.CRAFT')?.publicPath).toBe(
      '/craft-icons/compressed-encrypted.webp',
    );
    expect(getCraftArtifactIconForFile('readme.txt')).toBeUndefined();
  });
});
