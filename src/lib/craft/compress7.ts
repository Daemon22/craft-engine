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

import { brotliCompressSync, brotliDecompressSync, deflateSync, inflateSync, zstdCompressSync, zstdDecompressSync, constants as zlibConstants } from 'zlib';
import { compress as craftCodecCompress, decompress as craftCodecDecompress } from '@manya/craft-codec';

// ─────────────────────────────────────────────────────────────
// Strategy Types
// ─────────────────────────────────────────────────────────────

/** The compression strategies (0-12) */
export type CompressionStrategy = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

/** Craft-Codec is only tried below this size — it's O(256) work per symbol,
 *  so it's noticeably slower than Brotli/Zstd on large inputs, and its
 *  advantage is concentrated in text/structured data which is rarely huge. */
const CRAFT_CODEC_MAX_SIZE = 4 * 1024 * 1024;

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
// Fold 2: Delta Encoding
// ─────────────────────────────────────────────────────────────

/**
 * Delta encoding: store the difference between consecutive bytes.
 * Transforms [100, 102, 104, 106] → [100, 2, 2, 2]
 * This makes sequential/structured data extremely compressible.
 */
function deltaEncode(data: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  out[0] = data[0];
  for (let i = 1; i < data.length; i++) {
    out[i] = (data[i] - data[i - 1]) & 0xff;
  }
  return out;
}

/** Inverse of delta encoding — restores original byte sequence */
function deltaDecode(data: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  out[0] = data[0];
  for (let i = 1; i < data.length; i++) {
    out[i] = (out[i - 1] + data[i]) & 0xff;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
// Fold 3: Move-to-Front Transform
// ─────────────────────────────────────────────────────────────

/**
 * Move-to-Front transform (O(n) optimized with index map).
 * Replaces each byte with its position in a moving list.
 * Frequently occurring bytes get small indices, which compress
 * much better with entropy coders.
 *
 * Uses a direct index map (byte → position) for O(1) lookup
 * instead of the naive O(256) linear scan per byte.
 */
function mtfEncode(data: Buffer): Buffer {
  const alphabet = new Uint8Array(256);
  const indexMap = new Uint8Array(256); // byte -> position (inverse index)
  for (let i = 0; i < 256; i++) {
    alphabet[i] = i;
    indexMap[i] = i;
  }
  const out = Buffer.allocUnsafe(data.length);

  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    const pos = indexMap[byte];
    out[i] = pos;
    // Move to front: shift everything between 0..pos-1 right by 1
    if (pos > 0) {
      // Update index map for shifted bytes
      for (let j = pos; j > 0; j--) {
        const shiftedByte = alphabet[j - 1];
        alphabet[j] = shiftedByte;
        indexMap[shiftedByte] = j;
      }
      alphabet[0] = byte;
      indexMap[byte] = 0;
    }
  }
  return out;
}

/** Inverse of Move-to-Front transform (O(n) optimized) */
function mtfDecode(data: Buffer): Buffer {
  const alphabet = new Uint8Array(256);
  for (let i = 0; i < 256; i++) alphabet[i] = i;
  const out = Buffer.allocUnsafe(data.length);

  for (let i = 0; i < data.length; i++) {
    const pos = data[i];
    const byte = alphabet[pos];
    out[i] = byte;
    // Move to front
    if (pos > 0) {
      // Shift elements right by 1 from index 0 to pos-1
      for (let j = pos; j > 0; j--) {
        alphabet[j] = alphabet[j - 1];
      }
      alphabet[0] = byte;
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
// Fold 4: Run-Length Encoding
// ─────────────────────────────────────────────────────────────

/**
 * Run-Length Encoding: collapse repeated byte sequences.
 * [A, A, A, A, B, B] → [A, 4, B, 2]
 * Uses escape byte 0xFF for runs > 2. Single/double bytes pass through.
 */
function rleEncode(data: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let i = 0;

  while (i < data.length) {
    const byte = data[i];
    let run = 1;
    while (i + run < data.length && data[i + run] === byte && run < 255) {
      run++;
    }

    if (run >= 3) {
      // Emit: 0xFF (escape), byte, count
      chunks.push(Buffer.from([0xff, byte, run]));
      i += run;
    } else if (byte === 0xff) {
      // Escape the escape byte
      chunks.push(Buffer.from([0xff, 0xff, 1]));
      i += 1;
    } else {
      chunks.push(Buffer.from([byte]));
      i += 1;
    }
  }

  return Buffer.concat(chunks);
}

/** Inverse of Run-Length Encoding */
function rleDecode(data: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let i = 0;

  while (i < data.length) {
    if (data[i] === 0xff && i + 2 < data.length) {
      const byte = data[i + 1];
      const count = data[i + 2];
      chunks.push(Buffer.alloc(count, byte));
      i += 3;
    } else {
      chunks.push(Buffer.from([data[i]]));
      i += 1;
    }
  }

  return Buffer.concat(chunks);
}

// ─────────────────────────────────────────────────────────────
// Fold 5: Multi-Pair Byte-Pair Encoding (up to 4 pairs)
// ─────────────────────────────────────────────────────────────

/**
 * Multi-Pair Byte-Pair Encoding: iteratively find and replace the
 * most frequent byte pairs with unused bytes. Up to 4 pairs (or as
 * many unused bytes are available), whichever is fewer.
 *
 * Header format:
 *   [numPairs(1), pair1_replace(1), pair1_hi(1), pair1_lo(1),
 *                pair2_replace(1), pair2_hi(1), pair2_lo(1), ...]
 *
 * Each subsequent pair is found and replaced in the already-replaced
 * data, so later pairs can reference earlier replacement bytes.
 */
function bpeEncode(data: Buffer): Buffer {
  if (data.length < 4) return data;

  // Find unused bytes (0x00-0xFF not present in data)
  const used = new Set<number>();
  for (let i = 0; i < data.length; i++) used.add(data[i]);

  const unused: number[] = [];
  for (let b = 0; b < 256; b++) {
    if (!used.has(b)) unused.push(b);
  }

  if (unused.length === 0) return data; // All 256 bytes used, can't BPE

  const maxPairs = Math.min(4, unused.length);
  const pairs: Array<{ replacement: number; hi: number; lo: number }> = [];

  let currentData = data;

  for (let p = 0; p < maxPairs; p++) {
    // Find most frequent byte pair in current data
    const pairCounts = new Map<number, number>();
    for (let i = 0; i < currentData.length - 1; i++) {
      const pair = (currentData[i] << 8) | currentData[i + 1];
      pairCounts.set(pair, (pairCounts.get(pair) || 0) + 1);
    }

    let bestPair = 0;
    let bestCount = 0;
    for (const [pair, count] of pairCounts) {
      if (count > bestCount) {
        bestCount = count;
        bestPair = pair;
      }
    }

    // Only apply BPE if it actually reduces size
    // Each replacement saves (count-1) bytes, but we need 3 bytes per pair in header
    // Net savings: count - 1 - 3 = count - 4. Only worthwhile if count >= 4.
    if (bestCount < 4) break;

    const replacement = unused[p];
    const hi = (bestPair >> 8) & 0xff;
    const lo = bestPair & 0xff;

    pairs.push({ replacement, hi, lo });

    // Replace all occurrences of the pair in current data
    const result: number[] = [];
    let i = 0;
    while (i < currentData.length) {
      if (i < currentData.length - 1 && currentData[i] === hi && currentData[i + 1] === lo) {
        result.push(replacement);
        i += 2;
      } else {
        result.push(currentData[i]);
        i += 1;
      }
    }

    currentData = Buffer.from(result);
  }

  if (pairs.length === 0) return data;

  // Build header: [numPairs, pair1_replace, pair1_hi, pair1_lo, ...]
  const headerSize = 1 + pairs.length * 3;
  const header = Buffer.alloc(headerSize);
  header[0] = pairs.length;
  for (let p = 0; p < pairs.length; p++) {
    const offset = 1 + p * 3;
    header[offset] = pairs[p].replacement;
    header[offset + 1] = pairs[p].hi;
    header[offset + 2] = pairs[p].lo;
  }

  return Buffer.concat([header, currentData]);
}

/**
 * Inverse of Multi-Pair Byte-Pair Encoding.
 *
 * Decodes pairs in REVERSE order to avoid double-expansion issues.
 * Since later pairs are defined in terms of data that may contain
 * earlier replacement bytes, expanding the last pair first ensures
 * that earlier pair expansions don't accidentally create patterns
 * that would match later pairs.
 */
function bpeDecode(data: Buffer): Buffer {
  if (data.length < 5) return data;

  // Read header: number of BPE pairs defined
  const numPairs = data[0];
  if (numPairs === 0) return data.subarray(1);

  // Validate we have enough header bytes: 1 (count) + 3 per pair
  if (data.length < 1 + numPairs * 3) return data;

  const pairs: Array<{ replacement: number; hi: number; lo: number }> = [];
  let offset = 1;
  for (let p = 0; p < numPairs; p++) {
    pairs.push({
      replacement: data[offset],
      hi: data[offset + 1],
      lo: data[offset + 2],
    });
    offset += 3;
  }

  // Decode: process pairs in REVERSE order to avoid double-expansion
  // Each pair expansion is applied to the full data one at a time
  let currentData = data.subarray(offset);

  for (let p = numPairs - 1; p >= 0; p--) {
    const { replacement, hi, lo } = pairs[p];
    const result: number[] = [];

    for (let i = 0; i < currentData.length; i++) {
      if (currentData[i] === replacement) {
        result.push(hi, lo);
      } else {
        result.push(currentData[i]);
      }
    }

    currentData = Buffer.from(result);
  }

  return currentData;
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
