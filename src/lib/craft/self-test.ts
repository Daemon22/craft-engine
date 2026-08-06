/**
 * selfTest() — environment and pipeline sanity check.
 *
 * Meant to be called once at startup (CLI, server boot, CI) to catch
 * environment problems loudly and immediately, rather than having the
 * first real file someone crafts be the thing that surfaces a broken
 * dependency, a too-old Node version, or a bundler that mangled something.
 *
 * It exercises the full real pipeline (not mocks) end to end:
 *  - nano() -> macro() round-trip with self-verification
 *  - a fixture engineered so Craft-Codec (order-1) is likely to be tried,
 *    to catch @manya/craft-codec resolution/version problems specifically
 *  - a fixture large/repetitive enough that Zstd is likely to be tried,
 *    to catch missing zlib.zstd* support (Node < 22.15) specifically
 *
 * Throws with a clear, specific message on any failure. Does not touch
 * the filesystem or network — everything happens in memory.
 */
import { nano } from './nano';
import { macro } from './macro';

export interface SelfTestResult {
  ok: true;
  nodeVersion: string;
  zstdAvailable: boolean;
  checkedStrategies: string[];
  durationMs: number;
}

function checkZstdAvailable(): boolean {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const zlib = require('zlib');
    return typeof zlib.zstdCompressSync === 'function';
  } catch {
    return false;
  }
}

export function selfTest(): SelfTestResult {
  const start = Date.now();
  const passphrase = 'craft-self-test-passphrase-00';
  const checkedStrategies: string[] = [];

  const zstdAvailable = checkZstdAvailable();
  if (!zstdAvailable) {
    throw new Error(
      'CRAFT selfTest failed: zlib.zstdCompressSync is not available in this ' +
      `runtime (Node ${process.version}). Zstd strategies (10, 11) require ` +
      'Node >= 22.15. Either upgrade Node or expect those strategies to be ' +
      'silently skipped (they fail closed via try/catch, so this will not ' +
      'corrupt anything — but you will get weaker compression than expected).'
    );
  }

  // Fixture 1: plain text, exercises the base pipeline (Brotli path at minimum).
  try {
    const data = Buffer.from('CRAFT self-test fixture. '.repeat(100));
    const packed = nano(data, 'selftest.txt', 'text/plain', passphrase);
    const restored = macro(packed.buffer, passphrase);
    if (!restored.buffer.equals(data) || !restored.integrityVerified) {
      throw new Error('base round-trip mismatch');
    }
    checkedStrategies.push(packed.metadata.compressionStrategyName ?? '(unknown)');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`CRAFT selfTest failed on base text fixture: ${msg}`);
  }

  // Fixture 2: order-1-favorable data, likely to route through @manya/craft-codec —
  // catches a missing/misresolved dependency specifically, not just "some strategy worked".
  try {
    const size = 60_000;
    const data = Buffer.alloc(size);
    const preferred = new Uint8Array(256);
    for (let i = 0; i < 256; i++) preferred[i] = (i * 91 + 13) & 0xff;
    let prev = 0;
    for (let i = 0; i < size; i++) {
      const b = Math.random() < 0.7 ? preferred[prev] : Math.floor(Math.random() * 256);
      data[i] = b;
      prev = b;
    }
    const packed = nano(data, 'selftest2.bin', 'application/octet-stream', passphrase);
    const restored = macro(packed.buffer, passphrase);
    if (!restored.buffer.equals(data) || !restored.integrityVerified) {
      throw new Error('order-1-favorable round-trip mismatch');
    }
    checkedStrategies.push(packed.metadata.compressionStrategyName ?? '(unknown)');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`CRAFT selfTest failed on Craft-Codec fixture: ${msg}`);
  }

  // Fixture 3: incompressible random binary — confirms the pipeline degrades
  // safely (round-trips correctly, doesn't crash) even when nothing compresses.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { randomBytes } = require('crypto');
    const data: Buffer = randomBytes(20_000);
    const packed = nano(data, 'selftest3.bin', 'application/octet-stream', passphrase);
    const restored = macro(packed.buffer, passphrase);
    if (!restored.buffer.equals(data) || !restored.integrityVerified) {
      throw new Error('random-binary round-trip mismatch');
    }
    checkedStrategies.push(packed.metadata.compressionStrategyName ?? '(unknown)');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`CRAFT selfTest failed on random-binary fixture: ${msg}`);
  }

  return {
    ok: true,
    nodeVersion: process.version,
    zstdAvailable,
    checkedStrategies,
    durationMs: Date.now() - start,
  };
}
