/**
 * Adaptive order-1 context model.
 *
 * Predicts each byte from the byte immediately before it (256 separate
 * frequency tables, one per possible previous byte, each tracking counts
 * over the 256 possible next bytes). This is a fundamentally different
 * approach from what Brotli/Zstd do: they find repeated substrings and
 * entropy-code the leftovers; this predicts each byte from its immediate
 * context and lets the range coder spend fewer bits on more-predictable
 * bytes. It tends to do well on text and other data with strong local
 * statistical structure, and can lose to LZ-style matching on data with
 * long verbatim repeats — which is exactly why this plugs in as one more
 * adaptive candidate rather than a replacement.
 *
 * The model is purely adaptive (starts uniform, learns as it goes) so
 * the decoder can rebuild the identical state byte-by-byte without a
 * separate stats table shipped in the stream.
 */
import { RangeEncoder, RangeDecoder } from './range-coder';

const ALPHABET = 256;
const INCREMENT = 24; // how much a symbol's frequency grows per occurrence
const MAX_TOTAL = 1 << 15; // rescale before totals get large enough to strain range-coder precision

/**
 * One context's frequency table. Starts at all-1s (Laplace smoothing —
 * every symbol must have nonzero probability, or the coder couldn't
 * ever emit it) and adapts from there.
 */
class ContextTable {
  readonly freq = new Uint32Array(ALPHABET).fill(1);
  total = ALPHABET;

  cumFreqBelow(symbol: number): number {
    let sum = 0;
    for (let i = 0; i < symbol; i++) sum += this.freq[i];
    return sum;
  }

  update(symbol: number): void {
    this.freq[symbol] += INCREMENT;
    this.total += INCREMENT;
    if (this.total >= MAX_TOTAL) this.rescale();
  }

  private rescale(): void {
    let total = 0;
    for (let i = 0; i < ALPHABET; i++) {
      this.freq[i] = (this.freq[i] + 1) >> 1; // halve, keep >=1
      total += this.freq[i];
    }
    this.total = total;
  }

  /** Find the symbol whose cumulative range contains `target`. */
  findSymbol(target: number): { symbol: number; cumFreq: number; freq: number } {
    let cum = 0;
    for (let s = 0; s < ALPHABET; s++) {
      const f = this.freq[s];
      if (target < cum + f) {
        return { symbol: s, cumFreq: cum, freq: f };
      }
      cum += f;
    }
    // Should be unreachable if target < total; last symbol as a safe fallback.
    const last = ALPHABET - 1;
    return { symbol: last, cumFreq: cum - this.freq[last], freq: this.freq[last] };
  }
}

export function order1Encode(data: Buffer): Buffer {
  const contexts: ContextTable[] = Array.from({ length: ALPHABET }, () => new ContextTable());
  const enc = new RangeEncoder();
  let ctx = 0; // context = previous byte, starts at 0 for the first byte
  for (let i = 0; i < data.length; i++) {
    const symbol = data[i];
    const table = contexts[ctx];
    const cumFreq = table.cumFreqBelow(symbol);
    const freq = table.freq[symbol];
    enc.encode(cumFreq, freq, table.total);
    table.update(symbol);
    ctx = symbol;
  }
  return enc.finish();
}

export function order1Decode(compressed: Buffer, originalLength: number): Buffer {
  const contexts: ContextTable[] = Array.from({ length: ALPHABET }, () => new ContextTable());
  const dec = new RangeDecoder(compressed);
  const out = Buffer.alloc(originalLength);
  let ctx = 0;
  for (let i = 0; i < originalLength; i++) {
    const table = contexts[ctx];
    const target = dec.getFreq(table.total);
    const { symbol, cumFreq, freq } = table.findSymbol(target);
    dec.consume(cumFreq, freq);
    table.update(symbol);
    out[i] = symbol;
    ctx = symbol;
  }
  return out;
}
