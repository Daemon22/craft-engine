/**
 * Tests for the worker_threads offload layer (@craft/invokeAsync) wired into
 * the async compress7 engine.
 *
 * Covers:
 * - offloadTransform byte-identity for RLE/BPE at both the sync (< 256KB) and
 *   worker (>= 256KB) sizes
 * - Craft-Codec compress/decompress offloaded round-trip
 * - Event-loop responsiveness proof: the loop stays live while a large
 *   Craft-Codec decompress runs (would be ~0 ticks if it silently fell back to
 *   the synchronous codec)
 * - Strategy-12 (Craft-Codec) payloads restore through decompress7Async
 * - Full non-early-exit path exercises the RLE/BPE workers during compress
 */
import { describe, it, expect } from 'vitest';
import { randomBytes } from 'crypto';
import { compress as craftCodecCompress, decompress as craftCodecDecompress } from '@manya/craft-codec';
import {
  offloadTransform,
  craftCodecCompressAsync,
  craftCodecDecompressAsync,
  WORKER_OFFLOAD_MIN_SIZE,
} from '../src/lib/craft/invokeAsync';
import { rleEncode, rleDecode, bpeEncode, bpeDecode } from '../src/lib/craft/transforms';
import { compress7, decompress7, compress7Async, decompress7Async } from '../src/lib/craft/compress7';

/** Structured bytes that use fewer than all 256 values (so BPE does real work)
 *  and contain both runs and pairs. */
function structuredBytes(size: number): Buffer {
  const chunk = Buffer.from('The quick brown fox jumps over the lazy dog. '.repeat(20));
  const out = Buffer.alloc(size);
  for (let offset = 0; offset < size; offset += chunk.length) {
    const n = Math.min(chunk.length, size - offset);
    chunk.copy(out, offset, 0, n);
  }
  return out;
}

/** Order-1-favorable data — the sort of input where craft-codec wins. */
function order1Favorable(size: number): Buffer {
  const base = Buffer.from(
    'alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega '
  );
  const out = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    out[i] = base[i % base.length];
  }
  return out;
}

describe('worker offload: RLE/BPE transforms', () => {
  it('rleEncode is byte-identical below and at/above the offload threshold', async () => {
    const small = structuredBytes(16 * 1024);
    const large = structuredBytes(300 * 1024);

    expect(large.length).toBeGreaterThanOrEqual(WORKER_OFFLOAD_MIN_SIZE);

    expect(await offloadTransform('rleEncode', rleEncode, small)).toEqual(rleEncode(small));
    expect(await offloadTransform('rleEncode', rleEncode, large)).toEqual(rleEncode(large));
  });

  it('rleDecode inverts a worker-encoded buffer', async () => {
    const large = structuredBytes(300 * 1024);
    const encoded = rleEncode(large);
    const decoded = await offloadTransform('rleDecode', rleDecode, encoded);
    expect(decoded).toEqual(large);
  });

  it('bpeEncode/bpeDecode round-trip byte-identically at/above the threshold', async () => {
    const small = structuredBytes(16 * 1024);
    const large = structuredBytes(300 * 1024);

    expect(await offloadTransform('bpeEncode', bpeEncode, small)).toEqual(bpeEncode(small));
    expect(await offloadTransform('bpeEncode', bpeEncode, large)).toEqual(bpeEncode(large));

    const encoded = bpeEncode(large);
    expect(await offloadTransform('bpeDecode', bpeDecode, encoded)).toEqual(large);
  });
});

describe('worker offload: Craft-Codec', () => {
  it('craftCodecCompressAsync + craftCodecDecompressAsync round-trip', async () => {
    const data = order1Favorable(128 * 1024);
    const compressed = await craftCodecCompressAsync(data);
    const restored = await craftCodecDecompressAsync(compressed);
    expect(restored).toEqual(data);
    expect(compressed.length).toBeLessThan(data.length);
  });

  it('keeps the event loop responsive during a large legacy decompress', async () => {
    const data = order1Favorable(1024 * 1024);
    const payload = craftCodecCompress(data);

    let ticks = 0;
    const timer = setInterval(() => { ticks++; }, 5);

    const restored = await craftCodecDecompressAsync(payload);
    clearInterval(timer);

    expect(restored).toEqual(data);
    // A synchronous craft-codec decompress of ~1MB blocks the loop for ~1s and
    // lets the interval fire ~0 times; the worker path keeps the loop live.
    expect(ticks).toBeGreaterThan(0);
  });

  it('strategy-12 payloads restore through decompress7Async', async () => {
    const data = order1Favorable(512 * 1024);
    const payload = craftCodecCompress(data);
    const framed = Buffer.concat([Buffer.from([12]), payload]);

    const restored = await decompress7Async(framed);
    expect(restored).toEqual(data);
    // The sync engine's decompress handles the same frame too.
    expect(decompress7(framed)).toEqual(data);
  });
});

describe('async engine end-to-end with worker offload', () => {
  it('compress7Async + decompress7Async round-trip on a large non-early-exit input', async () => {
    // ~60% noise / ~40% structured text: Brotli cannot reach < 60% of the
    // original, so the FULL strategy set runs and the RLE/BPE workers fire.
    const noise = randomBytes(180 * 1024);
    const text = structuredBytes(120 * 1024);
    const data = Buffer.concat([noise, text]);

    const result = await compress7Async(data);
    expect(await decompress7Async(result.data)).toEqual(data);
    expect(decompress7(result.data)).toEqual(data);
  });

  it('sync-engine output still cross-decodes through the async engine after offload wiring', async () => {
    const data = order1Favorable(64 * 1024);
    const syncResult = compress7(data);
    expect(await decompress7Async(syncResult.data)).toEqual(data);
  });
});
