#!/usr/bin/env node
/**
 * CRAFT CLI — 7-Fold Compression Edition
 *
 * Usage:
 *   craft nano <file> -p <passphrase> [-o <output.craft>]
 *   craft macro <craft-file> -p <passphrase> [-o <output>]
 *   craft peek <craft-file>
 *   craft benchmark <file>
 *   craft checksum <file>
 *   craft version
 */

import * as fs from 'fs';
import * as path from 'path';
import { nano } from '../nano';
import { macro, peekMetadata } from '../macro';
import { compress7 } from '../compress7';
import { checksum } from '../integrity';
import { CRAFT_VERSION } from '../types';
import { selfTest } from '../self-test';
import {
  computeFixityRecord,
  verifyFixityRecord,
  serializeFixityRecord,
  parseFixityRecord,
  fixitySidecarPath,
} from '../fixity';

// ─── Streaming path (v4, constant-memory second execution path) ─────────
import { nanoStream } from '../nanoStream';
import { macroStream, peekStreamMetadata } from '../macroStream';
import { STREAM_VERSION, DEFAULT_STREAM_CHUNK_SIZE, NanoStreamResult, MacroStreamResult, StreamMetadata } from '../streamCore';
import { CRAFT_MAGIC } from '../types';

const colors = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m',
  red: '\x1b[31m', magenta: '\x1b[35m', amber: '\x1b[38;5;178m',
  teal: '\x1b[38;5;80m', emerald: '\x1b[38;5;35m',
};

function log(emoji: string, message: string) { console.log(`${colors.dim}[${emoji}]${colors.reset} ${message}`); }
function success(message: string) { console.log(`${colors.emerald}${colors.bold}  ✓${colors.reset} ${message}`); }

function recordFixitySidecar(craftFilePath: string, packageBuffer: Buffer, force: boolean): void {
  const record = computeFixityRecord(packageBuffer);
  const sidecarPath = fixitySidecarPath(craftFilePath);
  safeWriteFile(sidecarPath, Buffer.from(serializeFixityRecord(record), 'utf-8'), force);
}

/**
 * Write `data` to `outPath` with three safety properties:
 *  1. Never silently overwrites an existing file — requires --force.
 *  2. Atomic: writes to a temp file in the same directory first, then
 *     renames into place, so a crash or interruption mid-write can never
 *     leave a truncated/corrupt file at `outPath` (the original, if any,
 *     is untouched until the rename, which is effectively instantaneous).
 *  3. Reads the written file back and confirms it's byte-identical to
 *     what was meant to be written — catches filesystem-level write
 *     errors (full disk, permissions race, etc.) that would otherwise go
 *     unnoticed until someone tries to use the file later.
 */
function safeWriteFile(outPath: string, data: Buffer, force: boolean): void {
  if (fs.existsSync(outPath) && !force) {
    error(`Output file already exists: ${outPath}`);
    info(`Refusing to overwrite without confirmation. Re-run with --force to overwrite, or choose a different -o path.`);
    process.exit(1);
  }
  const dir = path.dirname(path.resolve(outPath));
  const tmpPath = path.join(dir, `.${path.basename(outPath)}.crafttmp-${process.pid}-${Date.now()}`);
  try {
    fs.writeFileSync(tmpPath, data);
    const writtenBack = fs.readFileSync(tmpPath);
    if (!writtenBack.equals(data)) {
      throw new Error('data read back from disk did not match what was written — possible filesystem write error');
    }
    fs.renameSync(tmpPath, outPath);
  } catch (err) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch { /* best-effort cleanup */ }
    const msg = err instanceof Error ? err.message : String(err);
    error(`Failed to write ${outPath} safely: ${msg}`);
    info(`Nothing was overwritten — any existing file at that path is untouched.`);
    process.exit(1);
  }
}
function error(message: string) { console.error(`${colors.red}${colors.bold}  ✗${colors.reset} ${message}`); }
function info(message: string) { console.log(`${colors.teal}  →${colors.reset} ${colors.dim}${message}${colors.reset}`); }

// ─── Streaming path (v4) helpers ──────────────────────────────────────────

/**
 * Read only the 7-byte CRAFT header (magic + version) without loading the whole
 * file. Returns the version byte (4 for v4 streaming archives), or 0 if the
 * file is too small / not a CRAFT package.
 */
function peekVersionFromFile(filePath: string): number {
  let fd: number | undefined;
  try {
    fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(7);
    let got = 0;
    while (got < 7) {
      const r = fs.readSync(fd, head, got, 7 - got, got);
      if (r === 0) break;
      got += r;
    }
    if (got < 7 || !head.subarray(0, 6).equals(CRAFT_MAGIC)) return 0;
    return head[6];
  } catch {
    return 0;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* best-effort */ } }
  }
}

/**
 * Passphrase strength rating
 */
function ratePassphrase(pp: string): { rating: string; filled: number; total: number; color: string } {
  const len = pp.length;
  const uniqueChars = new Set(pp).size;
  const hasUpper = /[A-Z]/.test(pp);
  const hasLower = /[a-z]/.test(pp);
  const hasDigit = /\d/.test(pp);
  const hasSymbol = /[^A-Za-z0-9]/.test(pp);
  const charMixCount = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;

  if (len < 12) {
    return { rating: 'Invalid', filled: Math.min(len, 4), total: 10, color: colors.red };
  }

  // Bonus for unique chars and character mix
  const uniqueBonus = Math.min(uniqueChars / len, 1); // 0-1
  const mixBonus = charMixCount / 4; // 0-1

  if (len < 16) {
    const filled = Math.round(3 + uniqueBonus * 2 + mixBonus * 2);
    return { rating: 'Basic', filled, total: 10, color: colors.amber };
  }
  if (len < 24) {
    const filled = Math.round(5 + uniqueBonus * 3 + mixBonus * 2);
    return { rating: 'Strong', filled, total: 10, color: colors.emerald };
  }
  const filled = Math.round(8 + uniqueBonus * 2);
  return { rating: 'Fortress', filled, total: 10, color: colors.teal };
}

function displayStrengthMeter(pp: string) {
  const { rating, filled, total, color } = ratePassphrase(pp);
  const bar = '█'.repeat(filled) + '░'.repeat(total - filled);
  success(`Passphrase strength: ${color}${bar}${colors.reset} ${color}${rating}${colors.reset} (${pp.length} chars)`);
}

/**
 * Format a compression-savings percentage for display. Tiny inputs can
 * end up LARGER after compression (container/format overhead exceeds
 * any savings) — `pct` is deliberately unclamped so this shows up
 * correctly as growth rather than silently wrapping into a nonsensical
 * negative "% saved".
 */
function formatSavingsLabel(pct: number): string {
  if (pct >= 0) return `${pct.toFixed(1)}% saved`;
  return `${Math.abs(pct).toFixed(1)}% larger (compression overhead on a small input)`;
}

/** A filled bar for savings; renders empty (not a misleading partial fill) when the input grew. */
function savingsBar(pct: number, width: number = 20): string {
  const filled = pct > 0 ? Math.max(1, Math.min(width, Math.round((pct / 100) * width))) : 0;
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function parseArgs(args: string[]): Record<string, string | boolean> {
  const parsed: Record<string, string | boolean> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('-')) {
      const key = arg.replace(/^-+/, '');
      const next = args[i + 1];
      if (next && !next.startsWith('-')) { parsed[key] = next; i++; }
      else { parsed[key] = true; }
    }
  }
  return parsed;
}

function getMime(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const map: Record<string, string> = {
    '.pdf': 'application/pdf', '.json': 'application/json', '.txt': 'text/plain',
    '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
    '.ts': 'application/typescript', '.png': 'image/png', '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml',
    '.zip': 'application/zip', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg',
    '.csv': 'text/csv', '.xml': 'application/xml', '.md': 'text/markdown',
  };
  return map[ext] || 'application/octet-stream';
}

function cmdNano(filePath: string, opts: Record<string, string | boolean>) {
  const passphrase = opts.p || opts.passphrase;
  const outputPath = opts.o || opts.output;
  if (!passphrase || typeof passphrase !== 'string') { error('Passphrase is required. Use -p <passphrase>'); process.exit(1); }
  if (passphrase.length < 12) {
    error(`Passphrase must be at least 12 characters (yours is ${passphrase.length}).`);
    const { rating, filled, total, color } = ratePassphrase(passphrase);
    const bar = '█'.repeat(filled) + '░'.repeat(total - filled);
    info(`Strength: ${color}${bar}${colors.reset} ${color}${rating}${colors.reset} — use 16+ chars with mixed case, digits & symbols for Strong rating`);
    process.exit(1);
  }
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }

  console.log('');
  log('⚙', `${colors.amber}${colors.bold}CRAFT Nano${colors.reset} — 7-Fold Compress & Encrypt`);
  console.log('');

  const data = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);
  const mime = getMime(filePath);

  info(`Input: ${fileName} (${formatBytes(data.length)})`);
  info(`Running 7-fold compression strategies...`);

  const startTime = performance.now();
  const result = nano(data, fileName, mime, passphrase, { compressionMode: '7fold' });
  const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);

  // Show strategy benchmarks
  if (result.strategyBenchmarks && result.strategyBenchmarks.length > 1) {
    console.log('');
    const sorted = [...result.strategyBenchmarks].sort((a, b) => a.size - b.size);
    for (const s of sorted) {
      const pct = data.length > 0 ? (1 - s.size / data.length) * 100 : 0;
      const isWinner = s.name === result.metadata.compressionStrategyName;
      const marker = isWinner ? `${colors.amber} ← WINNER${colors.reset}` : '';
      const line = `    #${s.strategy} ${s.name.padEnd(25)} ${formatBytes(s.size).padStart(10)}  (${formatSavingsLabel(pct)})${marker}`;
      console.log(isWinner ? `${colors.bold}${line}${colors.reset}` : line);
    }
  }

  console.log('');
  success(`Original:   ${formatBytes(result.metadata.originalSize)}`);
  success(`Compressed: ${formatBytes(result.metadata.compressedSize)}`);
  success(`Crafted:    ${formatBytes(result.buffer.length)}`);
  if (result.spaceSavedPercent > 0) {
    success(`Space saved: ${result.spaceSavedPercent.toFixed(1)}% (${formatBytes(result.spaceSaved)})`);
    // Compression ratio bar
    const ratioPct = result.spaceSavedPercent;
    const barFilled = Math.round((ratioPct / 100) * 20);
    const barEmpty = 20 - barFilled;
    const ratioBar = '█'.repeat(barFilled) + '░'.repeat(barEmpty);
    success(`Compression:  [${colors.emerald}${ratioBar}${colors.reset}] ${ratioPct.toFixed(1)}% smaller`);
  }
  success(`Strategy:   ${result.metadata.compressionStrategyName || 'brotli'}`);
  displayStrengthMeter(passphrase);
  success(`Completed in ${elapsed}s`);

  console.log('');
  info(`SHA-256: ${result.metadata.originalChecksum.slice(0, 16)}...`);

  const outPath = typeof outputPath === 'string' ? outputPath : filePath + '.craft';
  const force = opts.force === true || opts.f === true;
  safeWriteFile(outPath, result.buffer, force);
  recordFixitySidecar(outPath, result.buffer, force);
  console.log('');
  success(`Crafted package saved: ${outPath}`);
  success(`Fixity record saved: ${fixitySidecarPath(outPath)} (for future 'craft verify' checks)`);
  info(`(nano() already self-verified this package decrypts correctly before saving it — see NanoOptions.verify)`);
  console.log('');
}

function cmdMacro(filePath: string, opts: Record<string, string | boolean>) {
  const passphrase = opts.p || opts.passphrase;
  const outputPath = opts.o || opts.output;
  if (!passphrase || typeof passphrase !== 'string') { error('Passphrase is required. Use -p <passphrase>'); process.exit(1); }
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }

  console.log('');
  log('⚙', `${colors.teal}${colors.bold}CRAFT Macro${colors.reset} — Decrypt & Restore`);
  console.log('');

  const craftBuffer = fs.readFileSync(filePath);
  info(`Decrypting...`);
  info(`Decompressing (7-fold adaptive)...`);

  try {
    const startTime = performance.now();
    const result = macro(craftBuffer, passphrase);
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    console.log('');
    success(`Original name: ${result.metadata.originalName}`);
    success(`Restored size: ${formatBytes(result.buffer.length)}`);
    success(`Integrity:     ${result.integrityVerified ? `${colors.emerald}VERIFIED${colors.reset}` : `${colors.red}FAILED${colors.reset}`}`);
    if (result.metadata.compressionStrategyName) {
      success(`Strategy:      ${result.metadata.compressionStrategyName}`);
    }
    displayStrengthMeter(passphrase);
    success(`Completed in ${elapsed}s`);

    console.log('');
    info(`SHA-256: ${result.metadata.originalChecksum.slice(0, 16)}...`);

    // Default: save restored file alongside the input .craft file, using the original filename
    const inputDir = path.dirname(path.resolve(filePath));
    const defaultOutPath = path.join(inputDir, result.metadata.originalName);
    const outPath = typeof outputPath === 'string' ? outputPath : defaultOutPath;
    const force = opts.force === true || opts.f === true;
    safeWriteFile(outPath, result.buffer, force);
    console.log('');
    success(`Restored file saved: ${outPath}`);
    console.log('');
  } catch (err: unknown) {
    console.log('');
    if (err instanceof Error) {
      if (err.message.includes('auth tag') || err.message.includes('Unsupported state')) {
        error('Decryption failed — incorrect passphrase.');
      } else { error(err.message); }
    } else { error('Unknown error during Macro extraction.'); }
    process.exit(1);
  }
}

/**
 * Read just enough of a v4 archive from disk (the header region) to decrypt
 * its metadata WITHOUT loading the whole file — used to derive the default
 * restore filename for `craft macro-stream` without breaking constant memory.
 */
function peekStreamMetadataHead(filePath: string, passphrase: string): StreamMetadata | null {
  try {
    const fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(8192);
    let got = 0;
    try {
      while (got < head.length) {
        const r = fs.readSync(fd, head, got, head.length - got, got);
        if (r === 0) break;
        got += r;
      }
    } finally {
      fs.closeSync(fd);
    }
    if (got >= 7 && head.subarray(0, 6).equals(CRAFT_MAGIC) && head[6] === STREAM_VERSION) {
      return peekStreamMetadata(head.subarray(0, got), passphrase);
    }
  } catch { /* fall through → null */ }
  return null;
}

/**
 * craft nano-stream <file> -p <passphrase> [-o out.craft] [--force] ...
 * v4 (streaming, constant-memory) encode path. Streams the input straight off
 * disk into per-chunk AES-256-GCM + Zstd/Brotli, atomically written. The
 * existing `craft nano` is NOT replaced; `craft nano --stream` and
 * `craft nano-stream` both route here.
 */
async function cmdNanoStream(filePath: string, opts: Record<string, string | boolean>) {
  const passphrase = opts.p || opts.passphrase;
  const outputPath = opts.o || opts.output;
  if (!passphrase || typeof passphrase !== 'string') { error('Passphrase is required. Use -p <passphrase>'); process.exit(1); }
  if (passphrase.length < 12) {
    error(`Passphrase must be at least 12 characters (yours is ${passphrase.length}).`);
    const { rating, filled, total, color } = ratePassphrase(passphrase);
    const bar = '█'.repeat(filled) + '░'.repeat(total - filled);
    info(`Strength: ${color}${bar}${colors.reset} ${color}${rating}${colors.reset}`);
    process.exit(1);
  }
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }

  const fileName = path.basename(filePath);
  const mime = getMime(filePath);
  const outPath = typeof outputPath === 'string' ? outputPath : filePath + '.craft';
  const force = opts.force === true || opts.f === true;
  const chunkSize = typeof opts['chunk-size'] === 'string' ? parseInt(opts['chunk-size'], 10) : DEFAULT_STREAM_CHUNK_SIZE;
  const strategy: 'zstd' | 'brotli' = (typeof opts.strategy === 'string' && opts.strategy === 'brotli') ? 'brotli' : 'zstd';
  const level = typeof opts.level === 'string' ? parseInt(opts.level, 10) : undefined;
  const quality = typeof opts.quality === 'string' ? parseInt(opts.quality, 10) : undefined;
  const doVerify = opts['no-verify'] !== true;

  console.log('');
  log('⚙', `${colors.amber}${colors.bold}CRAFT Nano (streaming, v4)${colors.reset} — Constant-Memory Compress & Encrypt`);
  console.log('');
  info(`Input: ${fileName} (${formatBytes(fs.statSync(filePath).size)})`);
  info(`Strategy: ${strategy === 'zstd' ? 'Zstd' : 'Brotli'} | Chunk size: ${formatBytes(chunkSize)} | Output: ${outPath}`);

  const start = performance.now();
  let result: NanoStreamResult;
  try {
    result = await nanoStream(filePath, fileName, mime, passphrase, {
      output: outPath, force, chunkSize,
      compressionStrategy: strategy, level, quality, verify: doVerify,
    });
  } catch (err: unknown) {
    console.log('');
    error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  const elapsed = ((performance.now() - start) / 1000).toFixed(2);
  console.log('');
  success(`Original:     ${formatBytes(result.metadata.originalSize)}`);
  success(`Compressed:   ${formatBytes(result.metadata.compressedSize)}`);
  success(`Archive:      ${formatBytes(result.archiveBytes)}`);
  if (result.spaceSavedPercent > 0) {
    success(`Space saved: ${result.spaceSavedPercent.toFixed(1)}% (${formatBytes(result.spaceSaved)})`);
  }
  success(`Strategy:     ${result.metadata.compressionStrategyName || (strategy === 'zstd' ? 'Zstd' : 'Brotli')}`);
  success(`Chunks:       ${result.chunksProcessed} × ${formatBytes(chunkSize)}`);
  success(`Integrity:    ${result.integrityVerified ? `${colors.emerald}VERIFIED${colors.reset}` : `${colors.red}FAILED${colors.reset}`}`);
  displayStrengthMeter(passphrase);
  success(`Completed in ${elapsed}s`);
  console.log('');
  info(`SHA-256: ${result.metadata.originalChecksum.slice(0, 16)}...`);
  console.log('');
  success(`Crafted package saved: ${outPath}`);
  console.log('');
}

/**
 * craft macro-stream <file.craft> -p <passphrase> [-o out] [--force] ...
 * v4 (streaming, constant-memory) decode path. For v1–v3 archives it
 * transparently delegates to the gold-standard macro() (unchanged behaviour).
 */
async function cmdMacroStream(filePath: string, opts: Record<string, string | boolean>) {
  const passphrase = opts.p || opts.passphrase;
  const outputPath = opts.o || opts.output;
  if (!passphrase || typeof passphrase !== 'string') { error('Passphrase is required. Use -p <passphrase>'); process.exit(1); }
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }

  const version = peekVersionFromFile(filePath);
  const fileName = path.basename(filePath);
  const inputDir = path.dirname(path.resolve(filePath));
  const force = opts.force === true || opts.f === true;
  const chunkSize = typeof opts['chunk-size'] === 'string' ? parseInt(opts['chunk-size'], 10) : DEFAULT_STREAM_CHUNK_SIZE;

  // Resolve the default restore name WITHOUT loading the whole archive for v4.
  let defaultOutName: string | null = null;
  if (version === STREAM_VERSION) {
    const headMeta = peekStreamMetadataHead(filePath, passphrase as string);
    if (headMeta && headMeta.originalName && headMeta.originalName !== '[encrypted]') {
      defaultOutName = headMeta.originalName;
    }
  }
  const outPath = typeof outputPath === 'string' ? outputPath : (defaultOutName || fileName + '.restored');

  console.log('');
  log('⚙', `${colors.teal}${colors.bold}CRAFT Macro (streaming, v${version || '?'}) ${colors.reset} — Decrypt & Restore`);
  console.log('');
  info(`Input: ${fileName} | Output: ${outPath}`);

  const start = performance.now();
  let result: MacroStreamResult;
  try {
    result = await macroStream(filePath, passphrase as string, { output: outPath, force, chunkSize });
  } catch (err: unknown) {
    console.log('');
    if (err instanceof Error) {
      const m = err.message;
      if (m.includes('passphrase') || m.includes('auth tag') || m.includes('Unsupported state')) {
        error('Decryption failed — incorrect passphrase.');
      } else { error(m); }
    } else { error('Unknown error during Macro extraction.'); }
    process.exit(1);
  }

  const elapsed = ((performance.now() - start) / 1000).toFixed(2);
  console.log('');
  success(`Original name: ${result.metadata.originalName}`);
  success(`Restored size: ${formatBytes(result.bytesRestored)}`);
  success(`Integrity:     ${result.integrityVerified ? `${colors.emerald}VERIFIED${colors.reset}` : `${colors.red}FAILED${colors.reset}`}`);
  if (result.chunksRead > 0) success(`Chunks read:    ${result.chunksRead}`);
  displayStrengthMeter(passphrase as string);
  success(`Completed in ${elapsed}s`);
  console.log('');
  info(`SHA-256: ${result.metadata.originalChecksum.slice(0, 16)}...`);
  console.log('');
  success(`Restored file saved: ${outPath}`);
  console.log('');
}

function cmdBenchmark(filePath: string) {
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }

  console.log('');
  log('⚙', `${colors.amber}${colors.bold}CRAFT Benchmark${colors.reset} — 7-Fold Strategy Comparison`);
  console.log('');

  const data = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);

  info(`File: ${fileName} (${formatBytes(data.length)})`);
  info(`Running all compression strategies...`);
  console.log('');

  const result = compress7(data);
  const sorted = [...result.allResults].sort((a, b) => a.size - b.size);

  for (let i = 0; i < sorted.length; i++) {
    const s = sorted[i];
    const pct = data.length > 0 ? (1 - s.size / data.length) * 100 : 0;
    const isWinner = s.strategy === result.strategy;
    const rank = isWinner ? `${colors.amber}★${colors.reset}` : ` `;
    const bar = savingsBar(pct, 10);
    const barColor = pct >= 0 ? colors.emerald : colors.red;
    const marker = isWinner ? `${colors.amber} ← WINNER${colors.reset}` : '';

    console.log(`  ${rank} #${s.strategy} ${s.name.padEnd(25)} ${formatBytes(s.size).padStart(10)}  ${barColor}${bar}${colors.reset} ${formatSavingsLabel(pct)}${marker}`);
  }

  console.log('');
  success(`Best strategy: ${result.strategyName} (${formatBytes(result.compressedSize + 1)})`);
  const totalPct = data.length > 0 ? (1 - (result.compressedSize + 1) / data.length) * 100 : 0;
  success(`Total: ${formatSavingsLabel(totalPct)}`);
  console.log('');
}

function cmdPeek(filePath: string, opts: Record<string, string | boolean> = {}) {
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }
  const version = peekVersionFromFile(filePath);
  if (version === 0) { error('Not a valid CRAFT package (magic bytes mismatch).'); process.exit(1); }
  if (version === STREAM_VERSION) {
    // v4 streaming package — version-aware peek (no passphrase → redacted).
    const passphrase = typeof (opts.p || opts.passphrase) === 'string' ? (opts.p || opts.passphrase) as string : undefined;
    const craftBuffer = fs.readFileSync(filePath);
    console.log('');
    log('⚙', `${colors.cyan}${colors.bold}CRAFT Peek (streaming, v4)${colors.reset} — Package Inspection`);
    console.log('');
    try {
      const meta = peekStreamMetadata(craftBuffer, passphrase);
      success(`Archive version: ${meta.version} (streaming v4)`);
      success(`Original name:   ${meta.originalName}`);
      success(`Original size:   ${formatBytes(meta.originalSize)}`);
      success(`MIME type:       ${meta.originalMime}`);
      success(`Compression:     ${meta.compressionMode}${meta.compressionStrategyName ? ` (${meta.compressionStrategyName})` : ''}`);
      success(`Strategy:        ${meta.compressionStrategyKey || 'zstd'}`);
      success(`Encryption:      ${meta.encryptionAlgo} (AES-256-GCM, per-chunk)`);
      success(`Chunk table:     ${meta.chunkCount} chunks × ${formatBytes(meta.chunkSize)}`);
      const createdDisplay = meta.metadataEncrypted ? '[encrypted]' : new Date(meta.createdAt).toLocaleString();
      success(`Created:         ${createdDisplay}`);
      console.log('');
      info(`SHA-256: ${meta.originalChecksum}`);
      console.log('');
    } catch (err: unknown) {
      if (err instanceof Error) error(err.message);
      process.exit(1);
    }
    return;
  }
  // v1–v3: gold-standard peek (unchanged behaviour)
  console.log('');
  log('⚙', `${colors.cyan}${colors.bold}CRAFT Peek${colors.reset} — Package Inspection`);
  console.log('');
  const craftBuffer = fs.readFileSync(filePath);
  try {
    const meta = peekMetadata(craftBuffer);
    success(`Original name: ${meta.originalName}`);
    success(`Original size: ${formatBytes(meta.originalSize)}`);
    success(`MIME type:     ${meta.originalMime}`);
    success(`Compression:   ${meta.compressionMode || 'brotli'}${meta.compressionStrategyName ? ` (${meta.compressionStrategyName})` : ''}`);
    success(`Encryption:    ${meta.encryptionAlgo}`);
    const createdDisplay = meta.metadataEncrypted ? '[encrypted]' : new Date(meta.createdAt).toLocaleString();
    success(`Created:       ${createdDisplay}`);
    success(`Version:       ${meta.version}`);
    console.log('');
    info(`SHA-256: ${meta.originalChecksum}`);
    console.log('');
  } catch (err: unknown) {
    if (err instanceof Error) error(err.message);
    process.exit(1);
  }
}

function cmdChecksum(filePath: string) {
  if (!fs.existsSync(filePath)) { error(`File not found: ${filePath}`); process.exit(1); }
  const data = fs.readFileSync(filePath);
  console.log(`${checksum(data)}  ${path.basename(filePath)}`);
}

async function verifyOneFile(
  craftFilePath: string,
  deep: boolean,
  passphrase: string | undefined,
): Promise<{ status: 'OK' | 'MISMATCH' | 'UNTRACKED' | 'DEEP-FAIL' | 'DEEP-OK'; detail?: string }> {
  const version = peekVersionFromFile(craftFilePath);
  const sidecarPath = fixitySidecarPath(craftFilePath);

  let fixityStatus: 'OK' | 'MISMATCH' | 'UNTRACKED' = 'UNTRACKED';
  let fixityDetail: string | undefined;
  // Fixity (passive, whole-package SHA) is only possible with a sidecar record.
  // Lazy-load the whole package ONLY when a sidecar exists (v1–v3 behaviour).
  let packageBuffer: Buffer | undefined;
  if (fs.existsSync(sidecarPath)) {
    packageBuffer = fs.readFileSync(craftFilePath);
    try {
      const record = parseFixityRecord(fs.readFileSync(sidecarPath, 'utf-8'));
      const result = verifyFixityRecord(packageBuffer, record);
      fixityStatus = result.ok ? 'OK' : 'MISMATCH';
      fixityDetail = result.reason;
    } catch (err) {
      fixityStatus = 'MISMATCH';
      fixityDetail = err instanceof Error ? err.message : String(err);
    }
  }

  if (deep && passphrase) {
    try {
      if (version === STREAM_VERSION) {
        // v4: constant-memory streaming decrypt + SHA-256 verify (no whole-file load).
        const res = await macroStream(craftFilePath, passphrase, { verifyOnly: true });
        if (!res.integrityVerified) {
          return { status: 'DEEP-FAIL', detail: 'decrypted, but SHA-256 checksum of the restored data did not match' };
        }
        return { status: 'DEEP-OK', detail: fixityDetail };
      }
      // v1–v3: gold-standard macro() (unchanged behaviour — loads the package).
      const buf = packageBuffer ?? fs.readFileSync(craftFilePath);
      const result = macro(buf, passphrase);
      if (!result.integrityVerified) {
        return { status: 'DEEP-FAIL', detail: 'decrypted, but SHA-256 checksum of the restored data did not match' };
      }
      return { status: 'DEEP-OK', detail: fixityDetail };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { status: 'DEEP-FAIL', detail: msg };
    }
  }

  return { status: fixityStatus, detail: fixityDetail };
}

interface ScanSummary {
  okCount: number;
  mismatchCount: number;
  untrackedCount: number;
  results: Array<{ file: string; status: string; detail?: string }>;
}

async function runVerifyScan(targetPath: string, deep: boolean, passphrase: string | undefined): Promise<ScanSummary> {
  const stat = fs.statSync(targetPath);
  const files: string[] = stat.isDirectory()
    ? fs.readdirSync(targetPath).filter(f => f.endsWith('.craft')).map(f => path.join(targetPath, f))
    : [targetPath];

  const summary: ScanSummary = { okCount: 0, mismatchCount: 0, untrackedCount: 0, results: [] };
  for (const f of files) {
    const { status, detail } = await verifyOneFile(f, deep, passphrase);
    summary.results.push({ file: path.basename(f), status, detail });
    if (status === 'OK' || status === 'DEEP-OK') summary.okCount++;
    else if (status === 'UNTRACKED') summary.untrackedCount++;
    else summary.mismatchCount++;
  }
  return summary;
}

/** Parse a duration string like "30s", "5m", "1h", "1d" into milliseconds. */
function parseDuration(input: string): number {
  const match = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$/.exec(input.trim());
  if (!match) throw new Error(`Invalid duration: "${input}". Use forms like 30s, 5m, 1h, 1d.`);
  const value = parseFloat(match[1]);
  const unit = match[2] ?? 'ms';
  const multipliers: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return value * multipliers[unit];
}
async function cmdVerify(targetPath: string, opts: Record<string, string | boolean>) {
  if (!fs.existsSync(targetPath)) { error(`Path not found: ${targetPath}`); process.exit(1); }

  const deep = opts.deep === true;
  const passphrase = typeof (opts.p || opts.passphrase) === 'string' ? (opts.p || opts.passphrase) as string : undefined;
  if (deep && !passphrase) {
    error('--deep requires a passphrase: craft verify <path> --deep -p <passphrase>');
    process.exit(1);
  }

  let summary: ScanSummary;
  try {
    summary = await runVerifyScan(targetPath, deep, passphrase);
  } catch (err) {
    error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
  if (summary.results.length === 0) {
    info('No .craft files found to verify.');
    return;
  }

  console.log('');
  log('⚙', `${colors.teal}${colors.bold}CRAFT Verify${colors.reset} — fixity scan${deep ? ' (deep: full decrypt check)' : ' (passphrase-free)'}`);
  console.log('');

  for (const { file, status, detail } of summary.results) {
    if (status === 'OK' || status === 'DEEP-OK') {
      success(`${file}${colors.dim} — ${status}${detail ? ' (fixity: ' + detail + ')' : ''}${colors.reset}`);
    } else if (status === 'UNTRACKED') {
      info(`${file} — UNTRACKED (no fixity record; can't passively verify — re-craft it or run with --deep -p to check now)`);
    } else {
      error(`${file} — ${status}${detail ? ': ' + detail : ''}`);
    }
  }

  console.log('');
  success(`${summary.okCount} OK`);
  if (summary.untrackedCount > 0) info(`${summary.untrackedCount} untracked (no fixity record)`);
  if (summary.mismatchCount > 0) error(`${summary.mismatchCount} FAILED — these packages have changed since they were recorded, or fail to decrypt. Restore from backup.`);
  console.log('');

  if (summary.mismatchCount > 0) process.exit(1);
}

/**
 * craft watch — the scheduling half of fixity checking. `craft verify`
 * is a one-shot, scriptable check; this runs it repeatedly forever at a
 * fixed interval, so bitrot gets caught within one interval of happening
 * rather than only whenever someone happens to remember to run `verify`
 * by hand. Intended to be run as a long-lived process (see the systemd
 * unit / cron template in deploy/ for making that survive reboots).
 */
function cmdWatch(targetPath: string, opts: Record<string, string | boolean>) {
  if (!fs.existsSync(targetPath)) { error(`Path not found: ${targetPath}`); process.exit(1); }

  const deep = opts.deep === true;
  const passphrase = typeof (opts.p || opts.passphrase) === 'string' ? (opts.p || opts.passphrase) as string : undefined;
  if (deep && !passphrase) {
    error('--deep requires a passphrase: craft watch <path> --deep -p <passphrase>');
    process.exit(1);
  }
  const intervalStr = typeof opts.interval === 'string' ? opts.interval : '1h';
  let intervalMs: number;
  try {
    intervalMs = parseDuration(intervalStr);
  } catch (err) {
    error(err instanceof Error ? err.message : String(err));
    process.exit(1);
    return;
  }
  const logPath = typeof opts.log === 'string' ? opts.log : undefined;

  function writeLogLine(line: string): void {
    if (!logPath) return;
    try {
      fs.appendFileSync(logPath, line + '\n');
    } catch {
      // Best-effort: a logging failure shouldn't crash the watch loop itself.
    }
  }

  let scanInProgress = false;
  async function runOnce(): Promise<void> {
    if (scanInProgress) return; // never overlap a slow deep scan with the next interval tick
    scanInProgress = true;
    const timestamp = new Date().toISOString();
    let summary: ScanSummary;
    try {
      summary = await runVerifyScan(targetPath, deep, passphrase);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      error(`[${timestamp}] scan failed to run: ${msg}`);
      writeLogLine(`${timestamp} SCAN-ERROR ${msg}`);
      scanInProgress = false;
      return;
    }
    scanInProgress = false;
    if (summary.mismatchCount > 0) {
      error(`[${timestamp}] ${summary.mismatchCount} FAILED, ${summary.okCount} OK, ${summary.untrackedCount} untracked`);
      for (const r of summary.results) {
        if (r.status !== 'OK' && r.status !== 'DEEP-OK' && r.status !== 'UNTRACKED') {
          error(`    ${r.file} — ${r.status}${r.detail ? ': ' + r.detail : ''}`);
          writeLogLine(`${timestamp} FAIL ${r.file} ${r.status} ${r.detail ?? ''}`);
        }
      }
    } else {
      success(`[${timestamp}] ${summary.okCount} OK, ${summary.untrackedCount} untracked, 0 failed`);
      writeLogLine(`${timestamp} OK okCount=${summary.okCount} untracked=${summary.untrackedCount}`);
    }
  }

  console.log('');
  log('⚙', `${colors.teal}${colors.bold}CRAFT Watch${colors.reset} — scheduled fixity monitoring`);
  info(`Target: ${targetPath}`);
  info(`Interval: ${intervalStr}`);
  if (logPath) info(`Log file: ${logPath}`);
  info(`Mode: ${deep ? 'deep (full decrypt each cycle)' : 'passphrase-free (fixity checksum only)'}`);
  info(`Press Ctrl+C to stop.`);
  console.log('');

  runOnce(); // run immediately, then on the interval
  const handle = setInterval(runOnce, intervalMs);

  const shutdown = () => {
    clearInterval(handle);
    console.log('');
    info('craft watch stopped.');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function cmdVersion() {
  console.log(`Craft v${CRAFT_VERSION} — 7-Fold Nano/Macro Encryption & Compression Engine`);
  console.log('Brotli Q11 + Delta + MTF + RLE + BPE + Zstd + Craft-Codec + AES-256-GCM + SHA-256');
}

function cmdDoctor() {
  console.log('');
  log('⚙', `${colors.teal}${colors.bold}CRAFT Doctor${colors.reset} — environment & pipeline self-test`);
  console.log('');
  try {
    const result = selfTest();
    success(`Node version: ${result.nodeVersion}`);
    success(`Zstd support:  ${result.zstdAvailable ? 'available' : 'MISSING'}`);
    success(`Round-trip fixtures verified: ${result.checkedStrategies.length}`);
    for (const s of result.checkedStrategies) {
      success(`  strategy used: ${s}`);
    }
    success(`Completed in ${result.durationMs}ms`);
    console.log('');
    success(`All checks passed. This environment is safe to use for real files.`);
    console.log('');
  } catch (err) {
    console.log('');
    error(err instanceof Error ? err.message : String(err));
    console.log('');
    error(`Self-test FAILED. Do not trust this environment with real files until this is resolved.`);
    console.log('');
    process.exit(1);
  }
}

const args = process.argv.slice(2);
const command = args[0];
const filePath = args[1];
const opts = parseArgs(args.slice(2));

switch (command) {
  case 'nano':
    if (!filePath) { error('Usage: craft nano <file> -p <passphrase> [-o <output>]'); process.exit(1); }
    cmdNano(filePath, opts);
    break;
  case 'macro':
    if (!filePath) { error('Usage: craft macro <file.craft> -p <passphrase> [-o <output>]'); process.exit(1); }
    cmdMacro(filePath, opts);
    break;
  case 'peek':
    if (!filePath) { error('Usage: craft peek <file.craft> [-p <passphrase>]'); process.exit(1); }
    cmdPeek(filePath, opts);
    break;
  case 'benchmark':
    if (!filePath) { error('Usage: craft benchmark <file>'); process.exit(1); }
    cmdBenchmark(filePath);
    break;
  case 'checksum':
    if (!filePath) { error('Usage: craft checksum <file>'); process.exit(1); }
    cmdChecksum(filePath);
    break;
  case 'version': case '-v': case '--version':
    cmdVersion();
    break;
  case 'doctor':
    cmdDoctor();
    break;
  case 'verify':
    if (!filePath) { error('Usage: craft verify <file.craft | directory> [--deep -p <passphrase>]'); process.exit(1); }
    cmdVerify(filePath, opts);
    break;
  case 'watch':
    if (!filePath) { error('Usage: craft watch <directory> [--interval 1h] [--log <path>] [--deep -p <passphrase>]'); process.exit(1); }
    cmdWatch(filePath, opts);
    break;
  default:
    console.log('');
    console.log(`${colors.amber}${colors.bold}CRAFT${colors.reset} — 7-Fold Nano/Macro Encryption & Compression Engine`);
    console.log('');
    console.log('  craft nano <file> -p <passphrase> [-o output.craft] [--force]  7-Fold Compress & encrypt');
    console.log('  craft macro <file.craft> -p <passphrase> [-o output] [--force] Decrypt & restore');
    console.log('  craft benchmark <file>                                 Compare all strategies');
    console.log('  craft peek <file.craft>                                Inspect metadata');
    console.log('  craft checksum <file>                                  SHA-256 digest');
    console.log('  craft doctor                                           Verify this environment is safe to use');
    console.log('  craft verify <file.craft|dir> [--deep -p <pass>]       One-shot bitrot/corruption check');
    console.log('  craft watch <dir> [--interval 1h] [--log <path>]       Continuously re-verify on a schedule');
    console.log('  craft version                                         Show version');
    console.log('');
    break;
}
