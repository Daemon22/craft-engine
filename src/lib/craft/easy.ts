import * as fs from 'fs';
import * as path from 'path';
import { nano } from './nano';
import { macro } from './macro';
import { NanoOptions } from './types';

/**
 * The 'Easy' Facade for Craft Engine.
 * Designed for maximum capability with minimum code.
 */
export const craft = {
  /**
   * Pack a file (Compress + Encrypt) with one command.
   * Mirrors the simplicity of 'zip'.
   */
  async pack(inputPath: string, passphrase: string, options?: NanoOptions) {
    const data = fs.readFileSync(inputPath);
    const filename = path.basename(inputPath);

    // Auto-detect MIME or fallback
    const ext = path.extname(filename).toLowerCase();
    const mimeMap: Record<string, string> = {
      '.txt': 'text/plain',
      '.json': 'application/json',
      '.pdf': 'application/pdf',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.zip': 'application/zip'
    };
    const mime = mimeMap[ext] || 'application/octet-stream';

    const result = await nano(data, filename, mime, passphrase, options);
    const outputPath = inputPath + '.craft';

    fs.writeFileSync(outputPath, result.buffer);
    return { path: outputPath, result };
  },

  /**
   * Unpack a file (Decrypt + Decompress) with one command.
   * Mirrors the simplicity of 'unzip'.
   */
  async unpack(inputPath: string, passphrase: string) {
    const craftBuffer = fs.readFileSync(inputPath);
    const restored = await macro(craftBuffer, passphrase);

    // Determine output path: original name or strip .craft
    const outName = restored.metadata.originalName || path.basename(inputPath).replace('.craft', '');
    const outPath = path.join(path.dirname(inputPath), outName);

    fs.writeFileSync(outPath, restored.buffer);
    return { path: outPath, restored };
  }
};
