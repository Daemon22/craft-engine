/**
 * @manya/craft-codec — an original, format-aware compression codec.
 *
 * Not a wrapper around Brotli/Zstd: an adaptive order-1 context-modeling
 * range coder, implemented from scratch (see range-coder.ts and
 * order1-model.ts for the design rationale). Intended as one candidate
 * among several in craft-engine's adaptive strategy selector — it wins on
 * some inputs (structured/text data with strong local byte statistics)
 * and loses on others (data with long verbatim repeats, which LZ-style
 * matching in Brotli/Zstd captures better). The selector tries everything
 * and keeps the smallest, so this is additive by construction.
 */
import { order1Encode, order1Decode } from './order1-model';

export function compress(data: Buffer): Buffer {
  const body = order1Encode(data);
  const header = Buffer.alloc(4);
  header.writeUInt32BE(data.length, 0);
  return Buffer.concat([header, body]);
}

export function decompress(compressed: Buffer): Buffer {
  const originalLength = compressed.readUInt32BE(0);
  const body = compressed.subarray(4);
  return order1Decode(body, originalLength);
}

export { order1Encode, order1Decode } from './order1-model';
export { RangeEncoder, RangeDecoder } from './range-coder';
