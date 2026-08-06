/**
 * @craft/compress7 — 7-Fold Adaptive Compression Engine
 *
 * Seven compression strategies, each combining different pre-processing
 * transforms with Brotli Q11. The engine tries all strategies and
 * selects the smallest output.
 *
 * Strategy IDs (stored in compressed stream for decompression):
 *   0 = Raw Brotli Q11 (no pre-processing)
 *   1 = Delta + Brotli
 *   2 = MTF + Brotli
 *   3 = RLE + Brotli
 *   4 = BPE + Brotli
 *   5 = Delta + MTF + Brotli
 *   6 = Delta + RLE + Brotli
 *   7 = Double-pass Brotli
 */

import { brotliCompressSync, brotliDecompressSync, constants as zlibConstants } from 'zlib';

// ── Strategy Types ──────────────────────────────────────────────

/** The 7 compression strategies */
export type CompressionStrategy = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

/** Result from the 7-fold compression engine */
export interface Compress7Result {
  /** The compressed data (includes strategy prefix byte) */
  data: Buffer;
  /** Which strategy produced the smallest output */
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

// ── Delta Encoding ──────────────────────────────────────────────

/**
 * Delta encoding: store the difference between consecutive bytes.
 * Transforms [100, 102, 104, 106] → [100, 2, 2, 2].
 * Effective for sequential/structured data.
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

// ── Move-to-Front Transform ────────────────────────────────────

/**
 * Move-to-Front transform (O(n) optimized with index map).
 * Replaces each byte with its position in a moving list.
 * Frequently occurring bytes get small indices, improving
 * entropy coding efficiency.
 */
function mtfEncode(data: Buffer): Buffer {
  const alphabet = new Uint8Array(256);
  const indexMap = new Uint8Array(256); // byte → position (inverse index)
  for (let i = 0; i < 256; i++) {
    alphabet[i] = i;
    indexMap[i] = i;
  }
  const out = Buffer.allocUnsafe(data.length);

  for (let i = 0; i < data.length; i++) {
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
  return out;
}

/** Inverse of Move-to-Front transform */
function mtfDecode(data: Buffer): Buffer {
  const alphabet = new Uint8Array(256);
  for (let i = 0; i < 256; i++) alphabet[i] = i;
  const out = Buffer.allocUnsafe(data.length);

  for (let i = 0; i < data.length; i++) {
    const pos = data[i];
    const byte = alphabet[pos];
    out[i] = byte;
    if (pos > 0) {
      for (let j = pos; j > 0; j--) {
        alphabet[j] = alphabet[j - 1];
      }
      alphabet[0] = byte;
    }
  }
  return out;
}

// ── Run-Length Encoding ─────────────────────────────────────────

/**
 * Run-Length Encoding: collapse repeated byte sequences.
 * [A, A, A, A, B, B] → [A, 4, B, 2]
 * Uses escape byte 0xFF for runs ≥ 3. Shorter runs pass through.
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
      // Escape each 0xFF byte individually to avoid misinterpretation
      for (let r = 0; r < run; r++) {
        chunks.push(Buffer.from([0xff, 0xff, 1]));
      }
      i += run;
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

// ── Byte-Pair Encoding ─────────────────────────────────────────

/**
 * Byte-Pair Encoding: find the most frequent byte pair in the data
 * and replace it with an unused byte. Only applied when it reduces
 * the total size (minimum 4 occurrences to offset the 3-byte header).
 */
function bpeEncode(data: Buffer): Buffer {
  if (data.length < 4) return data;

  // Find unused bytes
  const used = new Set<number>();
  for (let i = 0; i < data.length; i++) used.add(data[i]);

  const unused: number[] = [];
  for (let b = 0; b < 256; b++) {
    if (!used.has(b)) unused.push(b);
  }

  if (unused.length === 0) return data; // All 256 bytes used, can't BPE

  // Find most frequent byte pair
  const pairCounts = new Map<number, number>();
  for (let i = 0; i < data.length - 1; i++) {
    const pair = (data[i] << 8) | data[i + 1];
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

  // Only apply BPE if it reduces size (3-byte header per pair definition)
  if (bestCount < 4) return data;

  const replacement = unused[0];
  const hi = (bestPair >> 8) & 0xff;
  const lo = bestPair & 0xff;

  // Header: [num_pairs(1), replacement(1), hi(1), lo(1)]
  const header = Buffer.from([1, replacement, hi, lo]);

  // Replace all occurrences of the pair
  const result: number[] = [];
  let i = 0;
  while (i < data.length) {
    if (i < data.length - 1 && data[i] === hi && data[i + 1] === lo) {
      result.push(replacement);
      i += 2;
    } else {
      result.push(data[i]);
      i += 1;
    }
  }

  return Buffer.concat([header, Buffer.from(result)]);
}

/** Inverse of Byte-Pair Encoding */
function bpeDecode(data: Buffer): Buffer {
  if (data.length < 5) return data;

  const numPairs = data[0];
  if (numPairs === 0) return data.subarray(1);

  if (data.length < 1 + numPairs * 3) return data;

  // O(1) lookup: replacement byte → [hi, lo]
  const hiMap = new Uint8Array(256);
  const loMap = new Uint8Array(256);
  const isReplacement = new Uint8Array(256);

  let offset = 1;
  for (let p = 0; p < numPairs; p++) {
    const replacement = data[offset];
    hiMap[replacement] = data[offset + 1];
    loMap[replacement] = data[offset + 2];
    isReplacement[replacement] = 1;
    offset += 3;
  }

  const result: number[] = [];
  while (offset < data.length) {
    const byte = data[offset];
    if (isReplacement[byte]) {
      result.push(hiMap[byte], loMap[byte]);
    } else {
      result.push(byte);
    }
    offset++;
  }

  return Buffer.from(result);
}

// ── Brotli Q11 ─────────────────────────────────────────────────

function brotliCompress(data: Buffer): Buffer {
  return brotliCompressSync(data, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
      [zlibConstants.BROTLI_PARAM_LGWIN]: 24,
    },
  });
}

// ── Adaptive Strategy Selection ────────────────────────────────

interface StrategyAttempt {
  strategy: CompressionStrategy;
  name: string;
  data: Buffer;
  compressed: Buffer;
}

/**
 * Try all compression strategies and return all results.
 * The caller selects the smallest.
 *
 * Performance note: deltaEncode(data) is a pure function of `data` needed
 * by strategies 1, 5, and 6 — computed once here and reused instead of
 * three independent recomputations. Strategy 7 reuses strategy 0's
 * already-computed Brotli output rather than recompressing `data` at
 * Q11 a second time (brotliCompressSync is deterministic, so the result
 * is identical either way — this just avoids doing the most expensive
 * step in the whole function twice).
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

  // Strategy 0: Raw Brotli Q11 (baseline)
  let c0: Buffer | undefined;
  try {
    c0 = brotliCompress(data);
    results.push({ strategy: 0, name: 'Brotli Q11', data, compressed: c0 });
  } catch { /* skip */ }

  // Shared transform for strategies 1, 5, 6 — computed once.
  let deltaOfData: Buffer | undefined;
  try {
    deltaOfData = deltaEncode(data);
  } catch { /* skip */ }

  // Strategy 1: Delta + Brotli
  if (deltaOfData) {
    try {
      const c1 = brotliCompress(deltaOfData);
      results.push({ strategy: 1, name: 'Delta + Brotli', data: deltaOfData, compressed: c1 });
    } catch { /* skip */ }
  }

  // Strategy 2: MTF + Brotli
  try {
    const mtf = mtfEncode(data);
    const c2 = brotliCompress(mtf);
    results.push({ strategy: 2, name: 'MTF + Brotli', data: mtf, compressed: c2 });
  } catch { /* skip */ }

  // Strategy 3: RLE + Brotli
  try {
    const rle = rleEncode(data);
    const c3 = brotliCompress(rle);
    results.push({ strategy: 3, name: 'RLE + Brotli', data: rle, compressed: c3 });
  } catch { /* skip */ }

  // Strategy 4: BPE + Brotli
  try {
    const bpe = bpeEncode(data);
    const c4 = brotliCompress(bpe);
    results.push({ strategy: 4, name: 'BPE + Brotli', data: bpe, compressed: c4 });
  } catch { /* skip */ }

  // Strategy 5: Delta + MTF + Brotli
  if (deltaOfData) {
    try {
      const mtf = mtfEncode(deltaOfData);
      const c5 = brotliCompress(mtf);
      results.push({ strategy: 5, name: 'Delta + MTF + Brotli', data: mtf, compressed: c5 });
    } catch { /* skip */ }
  }

  // Strategy 6: Delta + RLE + Brotli
  if (deltaOfData) {
    try {
      const rle = rleEncode(deltaOfData);
      const c6 = brotliCompress(rle);
      results.push({ strategy: 6, name: 'Delta + RLE + Brotli', data: rle, compressed: c6 });
    } catch { /* skip */ }
  }

  // Strategy 7: Double-pass Brotli (compress the compressed output).
  // Reuses c0 instead of a second brotliCompress(data) call.
  if (c0) {
    try {
      const first = c0;
      if (first.length > 64) { // Only try on non-trivial outputs
        const c7 = brotliCompress(first);
        if (c7.length < first.length) {
          results.push({ strategy: 7, name: 'Double-pass Brotli', data: first, compressed: c7 });
        }
      }
    } catch { /* skip */ }
  }

  return results;
}

// ── Public API ──────────────────────────────────────────────────

/**
 * 7-Fold Adaptive Compression: try all strategies, pick the best.
 *
 * Applies multiple pre-processing transforms and compression strategies,
 * then selects the smallest output. The strategy ID is prepended to
 * the compressed stream for correct decompression.
 *
 * @param data — The raw data to compress
 * @returns Compress7Result with the best strategy's output and benchmarks
 */
export function compress7(data: Buffer): Compress7Result {
  if (data.length === 0) {
    throw new Error('Cannot compress empty data. Provide non-empty input to Craft.');
  }

  const attempts = tryAllStrategies(data);

  // Fallback: if all strategies failed, use raw Brotli
  if (attempts.length === 0) {
    const fallback = brotliCompress(data);
    attempts.push({ strategy: 0, name: 'Brotli Q11 (fallback)', data, compressed: fallback });
  }

  // Select the strategy with the smallest compressed output (+1 byte for strategy ID)
  let best = attempts[0];
  for (const attempt of attempts) {
    if (attempt.compressed.length < best.compressed.length) {
      best = attempt;
    }
  }

  // Build result: [strategy_id_byte, ...compressed_data]
  const strategyByte = Buffer.from([best.strategy]);
  const finalData = Buffer.concat([strategyByte, best.compressed]);

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
 * 7-Fold Adaptive Decompression: reverse the winning strategy.
 *
 * Reads the strategy ID from the first byte, then applies the
 * correct inverse transforms in the correct order.
 *
 * @param compressed — The compressed data (with strategy prefix)
 * @returns Decompressed buffer (identical to original)
 */
export function decompress7(compressed: Buffer): Buffer {
  const strategy = compressed[0] as CompressionStrategy;
  const payload = compressed.subarray(1);

  // Step 1: Brotli decompress
  let data = brotliDecompressSync(payload);

  // Step 2: Apply inverse pre-processing based on strategy
  switch (strategy) {
    case 0: // Raw Brotli
      return data;

    case 1: // Delta + Brotli
      return deltaDecode(data);

    case 2: // MTF + Brotli
      return mtfDecode(data);

    case 3: // RLE + Brotli
      return rleDecode(data);

    case 4: // BPE + Brotli
      return bpeDecode(data);

    case 5: // Delta + MTF + Brotli
      const mtfResult = mtfDecode(data);
      return deltaDecode(mtfResult);

    case 6: // Delta + RLE + Brotli
      const rleResult = rleDecode(data);
      return deltaDecode(rleResult);

    case 7: // Double-pass Brotli — decompress twice
      return brotliDecompressSync(data);

    default:
      throw new Error(`Unknown compression strategy: ${strategy}`);
  }
}
