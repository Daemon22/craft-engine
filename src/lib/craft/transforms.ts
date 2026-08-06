/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/transforms — pure byte-stream pre-processing transforms
 * ═══════════════════════════════════════════════════════════════
 *
 *  The shared, side-effect-free pre-processing transforms used by the
 *  compress7 engine. Every function is a PURE function of its input Buffer —
 *  no closures, no module state, no imports of other modules. That purity is
 *  what lets the async engine serialize them with `fn.toString()` and run them
 *  inside a worker_threads eval worker (see ./invokeAsync). Keep them that way:
 *  do NOT add imports or capture module-level helpers here, or worker
 *  offloading will silently break.
 */

// ─────────────────────────────────────────────────────────────
// Fold 2: Delta Encoding
// ─────────────────────────────────────────────────────────────

/**
 * Delta encoding: store the difference between consecutive bytes.
 * Transforms [100, 102, 104, 106] → [100, 2, 2, 2]
 * This makes sequential/structured data extremely compressible.
 */
export function deltaEncode(data: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  out[0] = data[0];
  for (let i = 1; i < data.length; i++) {
    out[i] = (data[i] - data[i - 1]) & 0xff;
  }
  return out;
}

/** Inverse of delta encoding — restores original byte sequence */
export function deltaDecode(data: Buffer): Buffer {
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
export function mtfEncode(data: Buffer): Buffer {
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
export function mtfDecode(data: Buffer): Buffer {
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
export function rleEncode(data: Buffer): Buffer {
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
export function rleDecode(data: Buffer): Buffer {
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
export function bpeEncode(data: Buffer): Buffer {
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
export function bpeDecode(data: Buffer): Buffer {
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
