/**
 * Range coder — a carryless byte-oriented range coder.
 *
 * This is our own implementation of a well-established, publicly known
 * compression technique (range coding, in the "carryless" variant
 * popularized by Dmitry Subbotin). Unlike a plain arithmetic coder that
 * has to handle carry propagation across previously-emitted bytes (easy
 * to get subtly wrong), the carryless variant sacrifices a negligible
 * amount of coding efficiency (well under 0.01%) in exchange for a
 * renormalization rule that never needs to revisit already-output bytes.
 * That trade is worth it here: this coder backs a vault, and "slightly
 * less optimal but provably can't corrupt data" beats the reverse.
 *
 * Design in plain terms:
 *  - We track an interval [low, low+range) within a 32-bit unsigned space.
 *  - To encode a symbol occupying [cumFreq, cumFreq+freq) out of [0, tot),
 *    we narrow [low, low+range) to the matching sub-interval.
 *  - Whenever the top byte of `low` is guaranteed not to change again
 *    (either because the whole interval now shares that top byte, or
 *    because the interval has shrunk enough that we force it to), we
 *    emit that byte and shift the window left by 8 bits.
 *  - The decoder mirrors this exactly, using a "code" register instead
 *    of choosing symbols, and narrows the same way once it identifies
 *    which symbol the current code value falls into.
 *
 * Encoder and decoder are deterministic mirrors of each other bit for
 * bit, so as long as both sides compute cumFreq/freq/tot identically
 * (which is the adaptive model's job, in order1-model.ts), the coder
 * itself cannot desync.
 */

const TOP = 0x01000000; // 2^24 — renormalize when range drops below this
const BOTTOM = 0x00010000; // 2^16 — forced-renormalization threshold to avoid stalling

export class RangeEncoder {
  private low = 0; // uint32, tracked via >>> 0
  private range = 0xffffffff; // uint32
  private readonly bytes: number[] = [];

  /** Encode a symbol occupying [cumFreq, cumFreq+freq) out of [0, totFreq). */
  encode(cumFreq: number, freq: number, totFreq: number): void {
    this.range = Math.floor(this.range / totFreq);
    this.low = (this.low + cumFreq * this.range) >>> 0;
    this.range = this.range * freq;
    this.normalize();
  }

  private normalize(): void {
    // Case A: the top byte of the interval is fixed (low and low+range
    // agree on their top byte), so it's safe to emit it.
    // Case B: the range has shrunk so much further narrowing risks
    // getting stuck — force the range down to the remaining span within
    // the current top byte so Case A's condition will trigger.
    while (true) {
      if (((this.low ^ (this.low + this.range)) >>> 0) < TOP) {
        // top byte fixed
      } else if (this.range < BOTTOM) {
        this.range = (-this.low >>> 0) & (BOTTOM - 1);
        if (this.range === 0) this.range = BOTTOM; // guard: never let range hit 0
      } else {
        break;
      }
      this.bytes.push((this.low >>> 24) & 0xff);
      this.low = (this.low << 8) >>> 0;
      this.range = (this.range << 8) >>> 0;
      if (this.range === 0) this.range = 0xffffffff; // guard against total collapse
    }
  }

  /** Flush remaining state and return the encoded byte stream. */
  finish(): Buffer {
    // Emit enough bytes of `low` to disambiguate the final interval.
    for (let i = 0; i < 4; i++) {
      this.bytes.push((this.low >>> 24) & 0xff);
      this.low = (this.low << 8) >>> 0;
    }
    return Buffer.from(this.bytes);
  }
}

export class RangeDecoder {
  private low = 0;
  private range = 0xffffffff;
  private code = 0;
  private pos = 0;

  constructor(private readonly data: Buffer) {
    for (let i = 0; i < 4; i++) {
      this.code = ((this.code << 8) >>> 0) | this.nextByte();
    }
  }

  private nextByte(): number {
    return this.pos < this.data.length ? this.data[this.pos++] : 0;
  }

  /**
   * Given the total frequency for the current context, return the
   * cumulative-frequency value the current code falls at. The caller
   * (the adaptive model) uses this to look up which symbol that
   * corresponds to, then calls consume() with that symbol's exact
   * [cumFreq, freq) to narrow the interval identically to the encoder.
   */
  getFreq(totFreq: number): number {
    this.range = Math.floor(this.range / totFreq);
    const value = Math.floor(((this.code - this.low) >>> 0) / this.range);
    return value >= totFreq ? totFreq - 1 : value;
  }

  /** Narrow the interval to the decoded symbol's [cumFreq, cumFreq+freq). */
  consume(cumFreq: number, freq: number): void {
    this.low = (this.low + cumFreq * this.range) >>> 0;
    this.range = this.range * freq;
    this.normalize();
  }

  private normalize(): void {
    while (true) {
      if (((this.low ^ (this.low + this.range)) >>> 0) < TOP) {
        // top byte fixed
      } else if (this.range < BOTTOM) {
        this.range = (-this.low >>> 0) & (BOTTOM - 1);
        if (this.range === 0) this.range = BOTTOM;
      } else {
        break;
      }
      this.code = ((this.code << 8) >>> 0) | this.nextByte();
      this.low = (this.low << 8) >>> 0;
      this.range = (this.range << 8) >>> 0;
      if (this.range === 0) this.range = 0xffffffff;
    }
  }
}
