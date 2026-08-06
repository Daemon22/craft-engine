/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/compress7 — 12-Fold Adaptive Compression Engine
 *  The Living Canvas Edition — Upgraded
 * ═══════════════════════════════════════════════════════════════
 *
 *  Twelve folds of compression, each a different alchemy:
 *
 *  Fold 1: Analyze & Classify   — detect data patterns
 *  Fold 2: Delta Encode         — store differences between bytes
 *  Fold 3: Move-to-Front (MTF)  — make recurring symbols compress better
 *  Fold 4: Run-Length Encode    — collapse repeated byte sequences
 *  Fold 5: Byte-Pair Encode     — replace frequent byte pairs (multi-pair up to 4)
 *  Fold 6: Brotli Q11           — primary compression on pre-processed data
 *  Fold 7: Adaptive Selection   — try all strategies, pick the smallest
 *  Fold 8: Early-Exit Heuristic — skip expensive strategies for already-compressible data
 *  Fold 9: Multi-Strategy Combos — triple pre-processing pipelines
 *  Fold 10: Zstd (level 22)     — alternate entropy coder/matcher, wins on some inputs Brotli doesn't
 *  Fold 11: Delta + Zstd        — Zstd's matcher combined with delta pre-processing
 *  Fold 12: Craft-Codec         — original order-1 context-modeling range coder
 *                                  (@manya/craft-codec) — a genuinely different compression
 *                                  theory (adaptive statistical prediction, not LZ matching),
 *                                  wins on data with strong local byte structure (text, logs,
 *                                  config files). Gated to inputs <= 4MB since it's O(256) per
 *                                  symbol and slower than Brotli/Zstd.
 *
 *  Brotli, Zstd, and Craft-Codec are different algorithm families, so no
 *  one of them dominates the others — each wins on inputs the others
 *  don't. Since the engine already tries every strategy and keeps only
 *  the smallest result, adding more candidates can only help or tie; it
 *  never makes the chosen output larger.
 *
 *  The engine tries MULTIPLE strategy combinations and selects
 *  the one that produces the smallest output. This adaptive approach
 *  means Craft always finds the optimal compression path regardless
 *  of data type — text, JSON, binary, images, anything.
 *
 *  Strategy IDs (stored in compressed stream for decompression):
 *    0 = Raw Brotli Q11 (no pre-processing)
 *    1 = Delta + Brotli
 *    2 = MTF + Brotli
 *    3 = RLE + Brotli
 *    4 = BPE + Brotli (multi-pair BPE, up to 4 pairs)
 *    5 = Delta + MTF + Brotli
 *    6 = Delta + RLE + Brotli
 *    7 = Double-pass Brotli (compress pre-compressed output)
 *    8 = MTF + RLE + Brotli
 *    9 = Delta + BPE + Brotli
 *    10 = Raw Zstd (level 22, long window)
 *    11 = Delta + Zstd
 *    12 = Craft-Codec (order-1 adaptive range coder)
 */

import {
  brotliCompressSync,
  brotliDecompressSync,
  brotliCompress as brotliCompressCb,
  brotliDecompress as brotliDecompressCb,
  zstdCompressSync,
  zstdDecompressSync,
  zstdCompress as zstdCompressCb,
  zstdDecompress as zstdDecompressCb,
  constants as zlibConstants,
} from 'zlib';
import { compress as craftCodecCompress, decompress as craftCodecDecompress } from '@manya/craft-codec';
import { deltaEncode, deltaDecode, mtfEncode, mtfDecode, rleEncode, rleDecode, bpeEncode, bpeDecode } from './transforms';
import { offloadTransform, craftCodecCompressAsync, craftCodecDecompressAsync } from './invokeAsync';

// ─────────────────────────────────────────────────────────────
// Strategy Types
// ─────────────────────────────────────────────────────────────

/** The compression strategies (0-12) */
export type CompressionStrategy = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

/** Craft-Codec is only tried below this size — it's O(256) work per symbol,
 *  so it's noticeably slower than Brotli/Zstd on large inputs, and its
 *  advantage is concentrated in text/structured data which is rarely huge. */
const CRAFT_CODEC_MAX_SIZE = 4 * 1024 * 1024;

/** In the async engine, Craft-Codec runs off the main thread in a
 *  worker_threads eval worker (see ./invokeAsync), so it no longer stalls the
 *  event loop at all. This gate instead bounds the added compress LATENCY on
 *  the common path (and the worker CPU burned): Craft-Codec's win domain is
 *  small order-1-favorable data (measured <= ~60KB), so 128KB preserves every
 *  realistic case where it beats Brotli/Zstd. The sync engine keeps the larger
 *  CRAFT_CODEC_MAX_SIZE gate. */
const CRAFT_CODEC_ASYNC_MAX_SIZE = 128 * 1024;

/** Result from the adaptive compression engine */
export interface Compress7Result {
  /** The compressed data (includes strategy prefix byte) */
  data: Buffer;
  /** Which strategy won */
  strategy: CompressionStrategy;
  /** Strategy name for display */
  strategyName: string;
  /** Original size for ratio calculation */
  originalSize: number;
  /** Compressed size (without strategy byte) */
  compressedSize: number;
  /** All strategy results for benchmarking */
  allResults: Array<{
    strategy: CompressionStrategy;
    name: string;
    size: number;
  }>;
}

// ─────────────────────────────────────────────────────────────
// Fold 2/3/4/5 pre-processing transforms live in ./transforms (a pure module
// shared with the worker_threads offload layer). This file only keeps the
// async chunked variants used to keep multi-MB passes off the event loop.
// ─────────────────────────────────────────────────────────────

/** Byte budget per synchronous slice of the async pre-processing transforms.
 *  At ~1GB/s per slice this bounds each event-loop gap to well under a
 *  millisecond at chunk scale while keeping the codec's O(n) work on the main
 *  thread (these are pure JS — there is no native async variant). */
const TRANSFORM_SLICE_SIZE = 256 * 1024;

/** Async mirror of `deltaEncode` — byte-identical output, but processes the
 *  buffer in bounded slices and yields to the event loop between them, so a
 *  multi-MB delta pass no longer blocks the loop for hundreds of ms. */
async function deltaEncodeAsync(data: Buffer): Promise<Buffer> {
  const out = Buffer.alloc(data.length);
  if (data.length === 0) return out;
  out[0] = data[0];
  let prev = data[0];
  for (let start = 1; start < data.length; start += TRANSFORM_SLICE_SIZE) {
    const end = Math.min(start + TRANSFORM_SLICE_SIZE, data.length);
    for (let i = start; i < end; i++) {
      const b = data[i];
      out[i] = (b - prev) & 0xff;
      prev = b;
    }
    if (end < data.length) await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return out;
}

/** Async mirror of `mtfEncode` — byte-identical output (same alphabet/index-map
 *  state carried across slices), processing in bounded slices with yields. */
async function mtfEncodeAsync(data: Buffer): Promise<Buffer> {
  const alphabet = new Uint8Array(256);
  const indexMap = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    alphabet[i] = i;
    indexMap[i] = i;
  }
  const out = Buffer.allocUnsafe(data.length);
  for (let start = 0; start < data.length; start += TRANSFORM_SLICE_SIZE) {
    const end = Math.min(start + TRANSFORM_SLICE_SIZE, data.length);
    for (let i = start; i < end; i++) {
      const byte = data[i];
      const pos = indexMap[byte];
      out[i] = pos;
      if (pos > 0) {
        for (let j = pos; j > 0; j--) {
          const shiftedByte = alphabet[j - 1];
          alphabet[j] = shiftedByte;
          indexMap[shiftedByte] = j;
        }
        alphabet[0] = byte;
        indexMap[byte] = 0;
      }
    }
    if (end < data.length) await new Promise<void>((resolve) => setImmediate(resolve));
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
// Fold 6: Brotli Q11
// ─────────────────────────────────────────────────────────────

function brotliCompress(data: Buffer): Buffer {
  return brotliCompressSync(data, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
      [zlibConstants.BROTLI_PARAM_LGWIN]: 24,
    },
  });
}

/**
 * Zstd compression at max level (22) with a long match window.
 * Zstd uses a different match-finder and entropy coder than Brotli —
 * it doesn't dominate Brotli or vice versa, so trying both and keeping
 * the smaller result (which the adaptive selector already does) picks
 * up wins Brotli alone would miss. Requires Node >= 22.15 (zlib.zstd*).
 */
function zstdCompress(data: Buffer): Buffer {
  return zstdCompressSync(data, {
    params: {
      [zlibConstants.ZSTD_c_compressionLevel]: 22,
      [zlibConstants.ZSTD_c_windowLog]: 24,
    },
  });
}

// ─────────────────────────────────────────────────────────────
// Async codec helpers (libuv threadpool — off the main thread)
// ─────────────────────────────────────────────────────────────

/**
 * Async Brotli Q11 with identical parameters to `brotliCompress`. Runs on the
 * libuv threadpool so a large input no longer stalls the event loop, and
 * multiple concurrent calls parallelize across the pool. Brotli is
 * deterministic given fixed parameters, so the output is byte-identical to the
 * sync variant.
 */
function brotliCompressAsync(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    brotliCompressCb(data, {
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
        [zlibConstants.BROTLI_PARAM_LGWIN]: 24,
      },
    }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

function brotliDecompressAsync(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    brotliDecompressCb(data, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

/** Async Zstd L22 (long window) — mirror of `zstdCompress`, off the main thread.
 *  `pledgedSrcSize` is passed so the encoder emits a single-segment frame with a
 *  content-size header like the one-shot sync variant does; for large inputs the
 *  async frame can still differ from sync by a few header bytes (Node streams the
 *  input through the transform), but it stays a valid, deterministic, mutually
 *  decodable zstd frame. */
function zstdCompressAsync(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // `pledgedSrcSize` is supported by Node's runtime (see zlib.js Zstd ctor)
    // but not yet in @types/node — cast through the options parameter type.
    zstdCompressCb(data, {
      params: {
        [zlibConstants.ZSTD_c_compressionLevel]: 22,
        [zlibConstants.ZSTD_c_windowLog]: 24,
      },
      pledgedSrcSize: data.length,
    } as Parameters<typeof zstdCompressCb>[1], (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

function zstdDecompressAsync(data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zstdDecompressCb(data, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// ─────────────────────────────────────────────────────────────
// Fold 7: Adaptive Strategy Selection
// ─────────────────────────────────────────────────────────────

interface StrategyAttempt {
  strategy: CompressionStrategy;
  name: string;
  data: Buffer;
  compressed: Buffer;
}

/**
 * Try compression strategies and return all results.
 *
 * Early-exit optimization: if raw Brotli (strategy 0) already
 * compresses the data to < 60% of original size, the data is
 * already well-compressible and expensive pre-processing is
 * unlikely to help. In that case, only try strategies 0, 1, and 5
 * for coverage. Otherwise, try all 13 strategies (0-12).
 *
 * Performance note: several strategies share the same pre-processing
 * step (e.g. strategies 1, 5, 6, 9, and 11 all start with deltaEncode(data);
 * strategies 2 and 8 both start with mtfEncode(data)). Those shared
 * transforms are computed exactly once below and reused, rather than
 * being recomputed from scratch for every strategy that needs them —
 * they're pure functions of `data`, so this changes nothing about the
 * result, only how many times the same work gets done. Strategy 7
 * (double-pass Brotli) similarly reuses strategy 0's already-computed
 * Brotli output instead of recompressing `data` a second time at Q11,
 * which was previously the single most expensive piece of redundant
 * work in this function (a full extra max-quality Brotli pass on every
 * call, whether or not strategy 7 ended up winning).
 */
function tryAllStrategies(data: Buffer): StrategyAttempt[] {
  const results: StrategyAttempt[] = [];

  // For very small inputs (< 16 bytes), only try raw Brotli
  // Pre-processing transforms add overhead that doesn't pay off
  if (data.length < 16) {
    try {
      const c0 = brotliCompress(data);
      results.push({ strategy: 0, name: 'Brotli Q11', data, compressed: c0 });
    } catch { /* skip */ }
    return results;
  }

  // Strategy 0: Raw Brotli Q11 (baseline — always tried)
  let c0: Buffer | undefined;
  try {
    c0 = brotliCompress(data);
    results.push({ strategy: 0, name: 'Brotli Q11', data, compressed: c0 });
  } catch { /* skip */ }

  // Early-exit check: if Brotli already achieves < 60% of original size,
  // the data is well-compressible. Only try lightweight strategies.
  const rawBrotliResult = results.length > 0 ? results[0] : null;
  const earlyExit = rawBrotliResult !== null && rawBrotliResult.compressed.length < data.length * 0.6;

  // Shared transform, computed once and reused by every strategy that
  // needs delta-encoded data (1, 5, 6, 9, 11) instead of each one
  // recomputing deltaEncode(data) independently.
  let deltaOfData: Buffer | undefined;
  try {
    deltaOfData = deltaEncode(data);
  } catch { /* skip — dependent strategies below will no-op via the guard */ }

  // Strategy 1: Delta + Brotli (always tried for coverage)
  if (deltaOfData) {
    try {
      const c1 = brotliCompress(deltaOfData);
      results.push({ strategy: 1, name: 'Delta + Brotli', data: deltaOfData, compressed: c1 });
    } catch { /* skip */ }
  }

  // Strategy 5: Delta + MTF + Brotli (always tried for coverage)
  if (deltaOfData) {
    try {
      const mtf = mtfEncode(deltaOfData);
      const c5 = brotliCompress(mtf);
      results.push({ strategy: 5, name: 'Delta + MTF + Brotli', data: mtf, compressed: c5 });
    } catch { /* skip */ }
  }

  // If early-exit triggered, still try Zstd (fast) and Craft-Codec (if
  // under its size cap) for coverage, then return. Craft-Codec in
  // particular targets exactly this kind of data — strong local byte
  // statistics — so excluding it here (it's placed after this check in
  // the full strategy list below) would silently skip its best use case.
  if (earlyExit) {
    try {
      const c10 = zstdCompress(data);
      results.push({ strategy: 10, name: 'Zstd L22', data, compressed: c10 });
    } catch { /* skip */ }
    if (data.length <= CRAFT_CODEC_MAX_SIZE) {
      try {
        const c12 = craftCodecCompress(data);
        results.push({ strategy: 12, name: 'Craft-Codec (order-1)', data, compressed: c12 });
      } catch { /* skip */ }
    }
    return results;
  }

  // Shared transform, computed once and reused by strategies 2 and 8.
  let mtfOfData: Buffer | undefined;
  try {
    mtfOfData = mtfEncode(data);
  } catch { /* skip */ }

  // Strategy 2: MTF + Brotli
  if (mtfOfData) {
    try {
      const c2 = brotliCompress(mtfOfData);
      results.push({ strategy: 2, name: 'MTF + Brotli', data: mtfOfData, compressed: c2 });
    } catch { /* skip */ }
  }

  // Strategy 3: RLE + Brotli
  try {
    const rle = rleEncode(data);
    const c3 = brotliCompress(rle);
    results.push({ strategy: 3, name: 'RLE + Brotli', data: rle, compressed: c3 });
  } catch { /* skip */ }

  // Strategy 4: BPE + Brotli (now multi-pair BPE)
  try {
    const bpe = bpeEncode(data);
    const c4 = brotliCompress(bpe);
    results.push({ strategy: 4, name: 'BPE + Brotli', data: bpe, compressed: c4 });
  } catch { /* skip */ }

  // Strategy 6: Delta + RLE + Brotli (double pre-processing)
  if (deltaOfData) {
    try {
      const rle = rleEncode(deltaOfData);
      const c6 = brotliCompress(rle);
      results.push({ strategy: 6, name: 'Delta + RLE + Brotli', data: rle, compressed: c6 });
    } catch { /* skip */ }
  }

  // Strategy 7: Double-pass Brotli (compress the compressed output).
  // Reuses c0 (strategy 0's output) instead of recompressing `data` at
  // Q11 a second time — brotliCompressSync is a deterministic pure
  // function, so brotliCompress(data) here would always equal c0 anyway.
  if (c0) {
    try {
      const first = c0;
      if (first.length > 64) { // Only try on non-trivial outputs
        const c7 = brotliCompress(first);
        // Double-pass is only useful if the second pass is smaller
        if (c7.length < first.length) {
          results.push({ strategy: 7, name: 'Double-pass Brotli', data: first, compressed: c7 });
        }
      }
    } catch { /* skip */ }
  }

  // Strategy 8: MTF + RLE + Brotli
  // MTF creates small values which RLE can then pack efficiently
  if (mtfOfData) {
    try {
      const rle = rleEncode(mtfOfData);
      const c8 = brotliCompress(rle);
      results.push({ strategy: 8, name: 'MTF + RLE + Brotli', data: rle, compressed: c8 });
    } catch { /* skip */ }
  }

  // Strategy 9: Delta + BPE + Brotli
  // Delta encoding creates repetitive patterns that BPE can exploit
  if (deltaOfData) {
    try {
      const bpe = bpeEncode(deltaOfData);
      const c9 = brotliCompress(bpe);
      results.push({ strategy: 9, name: 'Delta + BPE + Brotli', data: bpe, compressed: c9 });
    } catch { /* skip */ }
  }

  // Strategy 10: Raw Zstd (level 22, long window)
  // Different match-finder/entropy coder than Brotli — wins on some
  // inputs (e.g. certain repetitive or already-mixed data) that Brotli
  // doesn't. Always worth trying since the selector only keeps the min.
  try {
    const c10 = zstdCompress(data);
    results.push({ strategy: 10, name: 'Zstd L22', data, compressed: c10 });
  } catch { /* skip */ }

  // Strategy 11: Delta + Zstd
  if (deltaOfData) {
    try {
      const c11 = zstdCompress(deltaOfData);
      results.push({ strategy: 11, name: 'Delta + Zstd', data: deltaOfData, compressed: c11 });
    } catch { /* skip */ }
  }

  // Strategy 12: Craft-Codec (original order-1 context-modeling range coder)
  // A genuinely different compression theory from Brotli/Zstd's LZ+entropy
  // approach — adaptive statistical prediction per byte. Gated by size
  // since it's slower; see CRAFT_CODEC_MAX_SIZE.
  if (data.length <= CRAFT_CODEC_MAX_SIZE) {
    try {
      const c12 = craftCodecCompress(data);
      results.push({ strategy: 12, name: 'Craft-Codec (order-1)', data, compressed: c12 });
    } catch { /* skip */ }
  }

  return results;
}

/**
 * Async mirror of `tryAllStrategies` — same strategy set, same selection
 * semantics, but Brotli/Zstd work runs on the libuv threadpool instead of the
 * main thread, so the event loop stays responsive while compressing and
 * concurrent calls parallelize across the pool.
 *
 * The deterministic early-exit decision (strategy 0 < 60% of original) is kept,
 * and the full-strategy batch is fired concurrently via Promise.allSettled.
 * Brotli is deterministic given fixed parameters, so every Brotli attempt (0-9)
 * is byte-identical to the sync engine's. Zstd frames (10, 11) are also
 * deterministic and valid but can differ from the sync engine's by a few frame
 * header bytes (Node's async zstd streams the input through a transform); both
 * variants decode interchangeably. The attempt list is assembled in the same
 * order as the sync version so the benchmark table (`allResults`) matches too.
 * Craft-Codec (12) is a synchronous pure-JS codec with no threadpool variant,
 * but it is offloaded to a worker_threads eval worker (see ./invokeAsync), so
 * it never stalls the event loop; it stays gated to inputs <=
 * CRAFT_CODEC_ASYNC_MAX_SIZE (~128KB) to bound compress latency, which fully
 * covers its win domain (small order-1-favorable data).
 */
async function tryAllStrategiesAsync(data: Buffer): Promise<StrategyAttempt[]> {
  const results: StrategyAttempt[] = [];

  // For very small inputs (< 16 bytes), only try raw Brotli.
  if (data.length < 16) {
    try {
      const c0 = await brotliCompressAsync(data);
      results.push({ strategy: 0, name: 'Brotli Q11', data, compressed: c0 });
    } catch { /* skip */ }
    return results;
  }

  // Strategy 0 (raw Brotli) fires first so its threadpool pass overlaps the
  // main-thread delta/MTF transforms below. Strategies 1 and 5 depend on those
  // transforms and fire as soon as their input is ready.
  const c0Promise = brotliCompressAsync(data);

  // Shared transform, computed once and reused by strategies 1, 5, 6, 9, 11.
  // Computed via the async chunked variant so a multi-MB delta pass yields to
  // the event loop (byte-identical to the sync `deltaEncode`).
  let deltaOfData: Buffer | undefined;
  try {
    deltaOfData = await deltaEncodeAsync(data);
  } catch { /* skip — dependent strategies below will no-op via the guard */ }

  const c1Promise = deltaOfData
    ? brotliCompressAsync(deltaOfData)
    : Promise.reject(new Error('deltaOfData unavailable'));
  const mtfOfDelta = deltaOfData ? await mtfEncodeAsync(deltaOfData) : undefined;
  const c5Promise = mtfOfDelta
    ? brotliCompressAsync(mtfOfDelta)
    : Promise.reject(new Error('mtfOfDelta unavailable'));

  const [c0Result, c1Result, c5Result] = await Promise.allSettled([
    c0Promise,
    c1Promise,
    c5Promise,
  ]);

  const c0 = c0Result.status === 'fulfilled' ? c0Result.value : undefined;
  if (c0) results.push({ strategy: 0, name: 'Brotli Q11', data, compressed: c0 });
  if (c1Result.status === 'fulfilled' && deltaOfData) {
    results.push({ strategy: 1, name: 'Delta + Brotli', data: deltaOfData, compressed: c1Result.value });
  }
  if (c5Result.status === 'fulfilled' && mtfOfDelta) {
    results.push({ strategy: 5, name: 'Delta + MTF + Brotli', data: mtfOfDelta, compressed: c5Result.value });
  }

  // Early-exit check: if Brotli already achieves < 60% of original size, the
  // data is well-compressible. Only try the lightweight coverage strategies.
  const earlyExit = c0 !== undefined && c0.length < data.length * 0.6;

  if (earlyExit) {
    try {
      const c10 = await zstdCompressAsync(data);
      results.push({ strategy: 10, name: 'Zstd L22', data, compressed: c10 });
    } catch { /* skip */ }
    if (data.length <= CRAFT_CODEC_ASYNC_MAX_SIZE) {
      try {
        const c12 = await craftCodecCompressAsync(data);
        results.push({ strategy: 12, name: 'Craft-Codec (order-1)', data, compressed: c12 });
      } catch { /* skip */ }
    }
    return results;
  }

  // ── Full strategy set ──
  // Shared transforms, computed once and reused across the strategies below.
  // mtfOfData uses the async chunked variant (byte-identical); RLE/BPE use
  // offloadTransform — worker-threaded at/above WORKER_OFFLOAD_MIN_SIZE so a
  // multi-MB allocation-heavy pass never stalls the loop (still byte-identical
  // to the sync functions either way). All five fire concurrently.
  let mtfOfData: Buffer | undefined;
  try {
    mtfOfData = await mtfEncodeAsync(data);
  } catch { /* skip */ }
  const [rleOfData, bpeOfData, rleOfDelta, rleOfMtf, bpeOfDelta] = await Promise.all([
    offloadTransform('rleEncode', rleEncode, data),
    offloadTransform('bpeEncode', bpeEncode, data),
    deltaOfData ? offloadTransform('rleEncode', rleEncode, deltaOfData) : Promise.resolve(undefined),
    mtfOfData ? offloadTransform('rleEncode', rleEncode, mtfOfData) : Promise.resolve(undefined),
    deltaOfData ? offloadTransform('bpeEncode', bpeEncode, deltaOfData) : Promise.resolve(undefined),
  ]);
  // Strategy 7 (double-pass) reuses c0's output (see sync version).
  const firstPass = c0 && c0.length > 64 ? c0 : undefined;

  // Fire every remaining Brotli/Zstd compression concurrently. Craft-Codec is
  // omitted here — it is offloaded and handled inline after the batch.
  const jobs: Array<{ strategy: number; name: string; data: Buffer; p: Promise<Buffer> }> = [];
  if (mtfOfData) jobs.push({ strategy: 2, name: 'MTF + Brotli', data: mtfOfData, p: brotliCompressAsync(mtfOfData) });
  jobs.push({ strategy: 3, name: 'RLE + Brotli', data: rleOfData, p: brotliCompressAsync(rleOfData) });
  jobs.push({ strategy: 4, name: 'BPE + Brotli', data: bpeOfData, p: brotliCompressAsync(bpeOfData) });
  if (deltaOfData && rleOfDelta) jobs.push({ strategy: 6, name: 'Delta + RLE + Brotli', data: rleOfDelta, p: brotliCompressAsync(rleOfDelta) });
  if (firstPass) jobs.push({ strategy: 7, name: 'Double-pass Brotli', data: c0 as Buffer, p: brotliCompressAsync(c0 as Buffer) });
  if (mtfOfData && rleOfMtf) jobs.push({ strategy: 8, name: 'MTF + RLE + Brotli', data: rleOfMtf, p: brotliCompressAsync(rleOfMtf) });
  if (deltaOfData && bpeOfDelta) jobs.push({ strategy: 9, name: 'Delta + BPE + Brotli', data: bpeOfDelta, p: brotliCompressAsync(bpeOfDelta) });
  jobs.push({ strategy: 10, name: 'Zstd L22', data, p: zstdCompressAsync(data) });
  if (deltaOfData) jobs.push({ strategy: 11, name: 'Delta + Zstd', data: deltaOfData, p: zstdCompressAsync(deltaOfData) });

  const settled = await Promise.allSettled(jobs.map(j => j.p));
  const byStrategy = new Map<number, { name: string; data: Buffer; compressed: Buffer }>();
  settled.forEach((s, i) => {
    if (s.status === 'fulfilled') {
      byStrategy.set(jobs[i].strategy, { name: jobs[i].name, data: jobs[i].data, compressed: s.value });
    }
  });

  const pushAttempt = (strategy: CompressionStrategy, name: string, data: Buffer, compressed: Buffer) => {
    results.push({ strategy, name, data, compressed });
  };

  if (byStrategy.has(2)) { const r = byStrategy.get(2)!; pushAttempt(2, r.name, r.data, r.compressed); }
  if (byStrategy.has(3)) { const r = byStrategy.get(3)!; pushAttempt(3, r.name, r.data, r.compressed); }
  if (byStrategy.has(4)) { const r = byStrategy.get(4)!; pushAttempt(4, r.name, r.data, r.compressed); }
  if (byStrategy.has(6)) { const r = byStrategy.get(6)!; pushAttempt(6, r.name, r.data, r.compressed); }

  // Strategy 7 is only useful if the second pass is smaller (mirrors sync).
  if (byStrategy.has(7) && c0) {
    const r = byStrategy.get(7)!;
    if (r.compressed.length < c0.length) pushAttempt(7, r.name, r.data, r.compressed);
  }

  if (byStrategy.has(8)) { const r = byStrategy.get(8)!; pushAttempt(8, r.name, r.data, r.compressed); }
  if (byStrategy.has(9)) { const r = byStrategy.get(9)!; pushAttempt(9, r.name, r.data, r.compressed); }
  if (byStrategy.has(10)) { const r = byStrategy.get(10)!; pushAttempt(10, r.name, r.data, r.compressed); }
  if (byStrategy.has(11)) { const r = byStrategy.get(11)!; pushAttempt(11, r.name, r.data, r.compressed); }

  // Strategy 12: Craft-Codec (offloaded to a worker thread — gated by the
  // async size cap so compress latency stays predictable).
  if (data.length <= CRAFT_CODEC_ASYNC_MAX_SIZE) {
    try {
      const c12 = await craftCodecCompressAsync(data);
      results.push({ strategy: 12, name: 'Craft-Codec (order-1)', data, compressed: c12 });
    } catch { /* skip */ }
  }

  return results;
}

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────

/**
 * Adaptive Compression: try all strategies, pick the best.
 *
 * This is the heart of Craft's compression power. Rather than
 * relying on a single algorithm, the engine applies multiple
 * pre-processing transforms and compression strategies, then
 * selects the one that produces the smallest output.
 *
 * The strategy ID is prepended to the compressed stream so
 * decompression knows exactly which inverse transforms to apply.
 *
 * @param data — The raw data to compress
 * @returns Compress7Result with the best strategy's output and benchmarks
 */
export function compress7(data: Buffer): Compress7Result {
  if (data.length === 0) {
    throw new Error('Cannot compress empty data. Provide non-empty input to Craft.');
  }

  const attempts = tryAllStrategies(data);

  // Safety: if all strategies failed, fall back to raw Brotli
  if (attempts.length === 0) {
    const fallback = brotliCompress(data);
    attempts.push({ strategy: 0, name: 'Brotli Q11 (fallback)', data, compressed: fallback });
  }

  return assembleResult(data, attempts);
}

/**
 * Async Adaptive Compression — byte-identical to `compress7`, but the
 * Brotli/Zstd passes run on the libuv threadpool so the event loop stays
 * responsive (and concurrent calls parallelize across the pool).
 *
 * @param data — The raw data to compress
 * @returns A Promise for the Compress7Result (same shape as `compress7`)
 */
export async function compress7Async(data: Buffer): Promise<Compress7Result> {
  if (data.length === 0) {
    throw new Error('Cannot compress empty data. Provide non-empty input to Craft.');
  }

  const attempts = await tryAllStrategiesAsync(data);

  // Safety: if all strategies failed, fall back to raw Brotli
  if (attempts.length === 0) {
    const fallback = await brotliCompressAsync(data);
    attempts.push({ strategy: 0, name: 'Brotli Q11 (fallback)', data, compressed: fallback });
  }

  return assembleResult(data, attempts);
}

/** Select the smallest strategy output and build the Compress7Result. */
function assembleResult(data: Buffer, attempts: StrategyAttempt[]): Compress7Result {
  // Select the strategy with the smallest compressed output
  // Add 1 byte overhead for the strategy ID prefix
  let best = attempts[0];
  for (const attempt of attempts) {
    if (attempt.compressed.length < best.compressed.length) {
      best = attempt;
    }
  }

  // Build result: [strategy_id_byte, ...compressed_data]
  const strategyByte = Buffer.from([best.strategy]);
  const finalData = Buffer.concat([strategyByte, best.compressed]);

  // Build benchmark table
  const allResults = attempts.map(a => ({
    strategy: a.strategy,
    name: a.name,
    size: a.compressed.length + 1, // +1 for strategy byte
  }));

  return {
    data: finalData,
    strategy: best.strategy,
    strategyName: best.name,
    originalSize: data.length,
    compressedSize: best.compressed.length,
    allResults,
  };
}

/**
 * Adaptive Decompression: reverse the winning strategy.
 *
 * Reads the strategy ID from the first byte, then applies the
 * correct inverse transforms in the correct order to restore
 * the original data.
 *
 * @param compressed — The compressed data (with strategy prefix)
 * @returns Decompressed buffer (bit-identical to original)
 */
export function decompress7(compressed: Buffer): Buffer {
  const strategy = compressed[0] as CompressionStrategy;
  const payload = compressed.subarray(1);

  // Strategy 12 uses its own self-contained codec (length header + range
  // coder), not Brotli or Zstd — handle it before the shared decompression step.
  if (strategy === 12) {
    return craftCodecDecompress(payload);
  }

  // Step 1: Decompress with the codec this strategy actually used.
  // Strategies 10 and 11 use Zstd; every other strategy uses Brotli.
  // (Getting this wrong doesn't crash cleanly — it silently hands
  // garbage bytes to the pre-processing inverse below — so it's
  // resolved explicitly per-strategy rather than assumed.)
  let data: Buffer;
  if (strategy === 10 || strategy === 11) {
    data = zstdDecompressSync(payload);
  } else {
    data = brotliDecompressSync(payload);
  }

  // Step 2: Apply inverse pre-processing based on strategy
  switch (strategy) {
    case 0: // Raw Brotli — no pre-processing was applied
      return data;

    case 1: // Delta + Brotli → inverse: Brotli decode, then delta decode
      return deltaDecode(data);

    case 2: // MTF + Brotli → inverse: Brotli decode, then MTF decode
      return mtfDecode(data);

    case 3: // RLE + Brotli → inverse: Brotli decode, then RLE decode
      return rleDecode(data);

    case 4: // BPE + Brotli → inverse: Brotli decode, then BPE decode
      return bpeDecode(data);

    case 5: // Delta + MTF + Brotli → inverse: Brotli decode, then MTF decode, then delta decode
      const mtfResult5 = mtfDecode(data);
      return deltaDecode(mtfResult5);

    case 6: // Delta + RLE + Brotli → inverse: Brotli decode, then RLE decode, then delta decode
      const rleResult6 = rleDecode(data);
      return deltaDecode(rleResult6);

    case 7: // Double-pass Brotli → inverse: decompress twice
      return brotliDecompressSync(data);

    case 8: // MTF + RLE + Brotli → inverse: Brotli decode, then RLE decode, then MTF decode
      const rleResult8 = rleDecode(data);
      return mtfDecode(rleResult8);

    case 9: // Delta + BPE + Brotli → inverse: Brotli decode, then BPE decode, then delta decode
      const bpeResult9 = bpeDecode(data);
      return deltaDecode(bpeResult9);

    case 10: // Raw Zstd — no pre-processing was applied
      return data;

    case 11: // Delta + Zstd → inverse: Zstd decode, then delta decode
      return deltaDecode(data);

    // Note: strategy 12 (Craft-Codec) is handled by the early return above,
    // before this switch — it never uses Brotli/Zstd decompression, so it
    // can't appear here (and TypeScript's control-flow narrowing agrees).

    default:
      throw new Error(`Unknown compression strategy: ${strategy}`);
  }
}

/**
 * Async Adaptive Decompression — byte-identical to `decompress7`, but the
 * Brotli/Zstd decode runs on the libuv threadpool and the Craft-Codec
 * (strategy 12) / RLE / BPE steps run in worker threads at/above
 * WORKER_OFFLOAD_MIN_SIZE, so a large restore never stalls the event loop.
 *
 * @param compressed — The compressed data (with strategy prefix)
 * @returns A Promise for the decompressed buffer (bit-identical to original)
 */
export async function decompress7Async(compressed: Buffer): Promise<Buffer> {
  const strategy = compressed[0] as CompressionStrategy;
  const payload = compressed.subarray(1);

  // Strategy 12 uses its own self-contained codec (length header + range
  // coder), not Brotli or Zstd — handle it before the shared decompression
  // step, offloaded so restoring a large legacy sync-engine payload can't
  // stall the loop.
  if (strategy === 12) {
    return craftCodecDecompressAsync(payload);
  }

  // Step 1: Decompress with the codec this strategy actually used.
  let data: Buffer;
  if (strategy === 10 || strategy === 11) {
    data = await zstdDecompressAsync(payload);
  } else {
    data = await brotliDecompressAsync(payload);
  }

  // Step 2: Apply inverse pre-processing based on strategy (same as sync).
  // RLE/BPE decodes offload at/above WORKER_OFFLOAD_MIN_SIZE (byte-identical);
  // delta/MTF decodes are ~1GB/s single-pass and stay on the main thread.
  switch (strategy) {
    case 0: // Raw Brotli — no pre-processing was applied
      return data;

    case 1: // Delta + Brotli → inverse: Brotli decode, then delta decode
      return deltaDecode(data);

    case 2: // MTF + Brotli → inverse: Brotli decode, then MTF decode
      return mtfDecode(data);

    case 3: // RLE + Brotli → inverse: Brotli decode, then RLE decode
      return offloadTransform('rleDecode', rleDecode, data);

    case 4: // BPE + Brotli → inverse: Brotli decode, then BPE decode
      return offloadTransform('bpeDecode', bpeDecode, data);

    case 5: // Delta + MTF + Brotli → inverse: Brotli decode, then MTF decode, then delta decode
      const mtfResult5 = mtfDecode(data);
      return deltaDecode(mtfResult5);

    case 6: // Delta + RLE + Brotli → inverse: Brotli decode, then RLE decode, then delta decode
      const rleResult6 = await offloadTransform('rleDecode', rleDecode, data);
      return deltaDecode(rleResult6);

    case 7: // Double-pass Brotli → inverse: decompress twice
      return brotliDecompressAsync(data);

    case 8: // MTF + RLE + Brotli → inverse: Brotli decode, then RLE decode, then MTF decode
      const rleResult8 = await offloadTransform('rleDecode', rleDecode, data);
      return mtfDecode(rleResult8);

    case 9: // Delta + BPE + Brotli → inverse: Brotli decode, then BPE decode, then delta decode
      const bpeResult9 = await offloadTransform('bpeDecode', bpeDecode, data);
      return deltaDecode(bpeResult9);

    case 10: // Raw Zstd — no pre-processing was applied
      return data;

    case 11: // Delta + Zstd → inverse: Zstd decode, then delta decode
      return deltaDecode(data);

    // Note: strategy 12 (Craft-Codec) is handled by the early return above.

    default:
      throw new Error(`Unknown compression strategy: ${strategy}`);
  }
}
