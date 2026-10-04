import * as fs from 'fs';
import * as path from 'path';
import { nano } from './nano';
import { nanoStream } from './nanoStream';
import { macroStream } from './macroStream';
import { NanoOptions, NanoResult } from './types';
import { CraftTier, getFeatures } from './features';

/**
 * The 'Brilliant' Facade for Craft Engine.
 * Maximizes potential by automatically selecting the most effective
 * execution path (Streaming vs In-Memory) based on file size and tier.
 */
export const craft = {
  /**
   * Pack a file with automatic resource management.
   * If the file is > 100MB, it automatically switches to constant-memory
   * streaming to prevent system crashes (OOM) if the tier allows it.
   */
  async pack(inputPath: string, passphrase: string, options?: NanoOptions & { tier?: CraftTier }) {
    if (!fs.existsSync(inputPath)) throw new Error(`File not found: ${inputPath}`);

    const stats = fs.statSync(inputPath);
    const tier = options?.tier || CraftTier.FREE;
    const features = getFeatures(tier);

    // Strict Tier Enforcement
    if (stats.size > (features.maxFileSize * 1024 * 1024)) {
      throw new Error(`File size (${(stats.size / 1024 / 1024).toFixed(1)}MB) exceeds the ${tier} tier limit.`);
    }

    const filename = path.basename(inputPath);
    const outputPath = inputPath + '.craft';

    // AUTO-SWITCH: If > 100MB and streaming is allowed, use the streaming path
    const STREAM_THRESHOLD = 100 * 1024 * 1024; // 100MB
    if (stats.size > STREAM_THRESHOLD && features.allowStreaming) {
      // Use v4 Streaming (Constant Memory)
      const result = await nanoStream(inputPath, filename, 'application/octet-stream', passphrase, {
        ...options,
        output: outputPath
      });
      return { path: outputPath, result, mode: 'streaming' };
    } else {
      // Use Gold-Standard 7-Fold (In-Memory)
      const data = fs.readFileSync(inputPath);
      const result = await nano(data, filename, 'application/octet-stream', passphrase, options);
      fs.writeFileSync(outputPath, result.buffer);
      return { path: outputPath, result, mode: 'in-memory' };
    }
  },

  /**
   * Unpack a file with automatic version detection.
   * Transparently handles legacy, single-file, and streaming v4 archives.
   */
  async unpack(inputPath: string, passphrase: string, options?: { output?: string }) {
    if (!fs.existsSync(inputPath)) throw new Error(`Archive not found: ${inputPath}`);

    // Use macroStream for ALL unpacks because it is a "universal reader"
    // that delegates v1-v3 to macro() and handles v4 natively.
    const outPath = options?.output || inputPath.replace('.craft', '');

    const result = await macroStream(inputPath, passphrase, {
      output: outPath,
      force: true
    });

    return { path: outPath, result };
  }
};
