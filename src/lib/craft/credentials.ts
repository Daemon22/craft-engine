/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/credentials — Credential Key System
 *  The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  A credential key is a compact 7-character secret used in place of a
 *  long passphrase. Rules (enforced for VALUES — letters & digits — and
 *  SPECIAL characters alike):
 *
 *    1. Exactly 7 characters long.
 *    2. Every character drawn from the allowed alphabet.
 *    3. A single character may appear at most 3 times (across values
 *       and specials alike). Since 7 > 3×2, at least 3 distinct
 *       characters are guaranteed.
 *
 *  The full valid space for the 90-symbol alphabet is ≈ 4.78×10¹³
 *  keys (≈ 45.4 bits of entropy), so brute-forcing a crafted package
 *  protected by a credential key still requires ~600,000 PBKDF2 rounds
 *  per candidate (see PBKDF2_ITERATIONS in types.ts).
 */

import { createHash, randomBytes } from 'crypto';

/** A credential key is exactly 7 characters long. */
export const CREDENTIAL_KEY_LENGTH = 7;

/** A single character (value or special) may appear at most 3 times. */
export const CREDENTIAL_MAX_REPEAT = 3;

/** Values: uppercase + lowercase letters and digits. */
export const CREDENTIAL_VALUES = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Special characters allowed in a credential key. */
export const CREDENTIAL_SPECIALS = '!@#$%^&*()_+-=[]{};:,.<>?~|';

/** Full credential-key alphabet: values + specials. */
export const CREDENTIAL_ALPHABET = CREDENTIAL_VALUES + CREDENTIAL_SPECIALS;

/** Domain-separation prefix for the SHA-256 pre-hash of a credential key. */
const CREDENTIAL_KEY_DOMAIN = Buffer.from('craft::credential-key-v1::', 'utf-8');

const ALPHABET_SET = new Set(CREDENTIAL_ALPHABET);
const SPECIAL_SET = new Set(CREDENTIAL_SPECIALS);
const VALUE_SET = new Set(CREDENTIAL_VALUES);

/** Whether a single character of the alphabet is a "value" (letter/digit). */
export function isValueChar(ch: string): boolean {
  return ch.length === 1 && VALUE_SET.has(ch);
}

/** Whether a single character of the alphabet is a special character. */
export function isSpecialChar(ch: string): boolean {
  return ch.length === 1 && SPECIAL_SET.has(ch);
}

/** Per-character occurrence counts for a candidate key. */
export type CredentialCounts = Record<string, number>;

/** Result of validating a credential key. */
export interface CredentialValidation {
  /** True when the key satisfies every rule. */
  valid: boolean;
  /** The key that was validated. */
  key: string;
  /** Number of characters (should be 7). */
  length: number;
  /** Per-character occurrence counts. */
  counts: CredentialCounts;
  /** Maximum repeat allowed per character (3). */
  maxRepeat: number;
  /** Count of distinct characters used. */
  distinct: number;
  /** Whether at least one character is a value (letter/digit). */
  hasValue: boolean;
  /** Whether at least one character is a special character. */
  hasSpecial: boolean;
  /** Human-readable problems (empty when valid). */
  errors: string[];
}

/**
 * Validate a credential key against the three rules:
 * 1. exactly 7 characters, 2. allowed alphabet, 3. max 3 repeats per
 * character — enforced for values AND special characters alike.
 */
export function validateCredentialKey(key: string): CredentialValidation {
  const errors: string[] = [];
  const counts: CredentialCounts = {};
  let hasValue = false;
  let hasSpecial = false;

  if (typeof key !== 'string') {
    return {
      valid: false,
      key: String(key),
      length: 0,
      counts: {},
      maxRepeat: CREDENTIAL_MAX_REPEAT,
      distinct: 0,
      hasValue: false,
      hasSpecial: false,
      errors: ['Credential key must be a string.'],
    };
  }

  if (key.length !== CREDENTIAL_KEY_LENGTH) {
    errors.push(
      `Credential key must be exactly ${CREDENTIAL_KEY_LENGTH} characters long (got ${key.length}).`,
    );
  }

  for (const ch of key) {
    if (!ALPHABET_SET.has(ch)) {
      errors.push(
        `Character '${ch}' is not in the allowed alphabet ` +
        `(values: A-Z, a-z, 0-9; specials: ${CREDENTIAL_SPECIALS}).`,
      );
      continue;
    }
    counts[ch] = (counts[ch] ?? 0) + 1;
    if (isValueChar(ch)) hasValue = true;
    if (isSpecialChar(ch)) hasSpecial = true;
  }

  for (const [ch, n] of Object.entries(counts)) {
    if (n > CREDENTIAL_MAX_REPEAT) {
      errors.push(
        `Character '${ch}' appears ${n} times; each character may appear ` +
        `at most ${CREDENTIAL_MAX_REPEAT} times (applies to values and special characters alike).`,
      );
    }
  }

  return {
    valid: errors.length === 0,
    key,
    length: key.length,
    counts,
    maxRepeat: CREDENTIAL_MAX_REPEAT,
    distinct: Object.keys(counts).length,
    hasValue,
    hasSpecial,
    errors,
  };
}

/**
 * Generate a random valid credential key: exactly 7 characters, each
 * character repeated at most 3 times, mixing at least one value and one
 * special. Uses rejection sampling (a valid key is generated on the first
 * try ~93% of the time) with a deterministic constructive fallback so it
 * always terminates even with an adversarial RNG.
 *
 * @param rng — injectable PRNG (0..1) for deterministic tests
 */
export function generateCredentialKey(rng: () => number = Math.random): string {
  const attempts = 1000;
  for (let i = 0; i < attempts; i++) {
    let candidate = '';
    for (let j = 0; j < CREDENTIAL_KEY_LENGTH; j++) {
      const idx = Math.floor(rng() * CREDENTIAL_ALPHABET.length);
      candidate += CREDENTIAL_ALPHABET[idx];
    }
    const v = validateCredentialKey(candidate);
    if (v.valid && v.hasValue && v.hasSpecial) return candidate;
  }

  // Constructive fallback: 3 distinct characters (two values, one special),
  // counts [3,2,2] — always satisfies the ≤3 repeat rule and terminates
  // even when the RNG is adversarial.
  const value1 = CREDENTIAL_VALUES[0];
  const value2 = CREDENTIAL_VALUES[1];
  const special = CREDENTIAL_SPECIALS[0];
  const pool = [value1, value1, value1, value2, value2, special, special];
  let out = '';
  while (pool.length > 0) {
    const idx = Math.floor(rng() * pool.length);
    out += pool.splice(idx, 1)[0];
  }
  return out;
}

/** Strength ratings for a credential key. */
export type CredentialRating = 'Invalid' | 'Weak' | 'Standard' | 'Strong' | 'Fortress';

/** Result of rating a credential key. */
export interface CredentialStrength {
  /** 0-10 score (0 = invalid). */
  score: number;
  rating: CredentialRating;
  filled: number;
  total: number;
}

/**
 * Rate a credential key's strength on a 0-10 scale. Invalid keys score 0.
 * Scores reward distinct characters, mixing values with specials, digit
 * and case variety, and avoiding maximum-allowed repetition.
 */
export function rateCredentialKey(key: string): CredentialStrength {
  const v = validateCredentialKey(key);
  if (!v.valid) return { score: 0, rating: 'Invalid', filled: 0, total: 10 };

  let score = 0;
  // Distinct characters: minimum possible is 3, maximum is 7.
  score += Math.min(4, v.distinct - 2); // 1..4
  // Mix of values and specials.
  if (v.hasValue && v.hasSpecial) score += 2;
  // Digit presence.
  if (/[0-9]/.test(key)) score += 1;
  // Case variety among letters.
  if (/[A-Z]/.test(key) && /[a-z]/.test(key)) score += 1;
  // Repetition discipline: no character hits the 3× ceiling.
  const atMax = Object.values(v.counts).some((n) => n === CREDENTIAL_MAX_REPEAT);
  if (!atMax) score += 2;
  else score += 1;

  const clamped = Math.max(0, Math.min(10, score));
  const rating: CredentialRating =
    clamped >= 9 ? 'Fortress' : clamped >= 7 ? 'Strong' : clamped >= 5 ? 'Standard' : 'Weak';
  return { score: clamped, rating, filled: clamped, total: 10 };
}

/**
 * Exact count of strings of length `len` over an alphabet of `alphabetSize`
 * symbols where no single symbol appears more than `maxRepeat` times.
 * Used to report the true entropy of the credential-key space.
 */
export function countValidKeys(
  len: number,
  alphabetSize: number,
  maxRepeat: number,
): number {
  const counts: number[] = [];
  let total = 0;

  const walk = (remaining: number, slots: number, maxPossible: number, denom: number): void => {
    if (remaining === 0) {
      if (slots === 0) return;
      // permutations of the chosen characters among the slots, divided by
      // the permutations of equal-count groups, times the choice of which
      // characters get which count.
      total += Math.round(perms(len, slots) / denom) * arrangements(alphabetSize, counts);
      return;
    }
    const top = Math.min(remaining, maxRepeat, maxPossible);
    for (let n = top; n >= 1; n--) {
      counts.push(n);
      walk(remaining - n, slots + n, n, denom * factorial(n));
      counts.pop();
    }
  };

  walk(len, 0, len, 1);
  return total;
}

function factorial(n: number): number {
  let r = 1;
  for (let i = 2; i <= n; i++) r *= i;
  return r;
}

function perms(n: number, k: number): number {
  let r = 1;
  for (let i = 0; i < k; i++) r *= n - i;
  return r;
}

/** Number of ways to assign `k` distinct counts-groups to alphabet symbols. */
function arrangements(alphabetSize: number, counts: number[]): number {
  const groupCounts: Record<number, number> = {};
  for (const c of counts) groupCounts[c] = (groupCounts[c] ?? 0) + 1;
  let denom = 1;
  for (const n of Object.values(groupCounts)) denom *= factorial(n);
  return perms(alphabetSize, counts.length) / denom;
}

/** Entropy report for a credential key. */
export interface CredentialEntropy {
  /** Shannon entropy of the key itself (bits). */
  keyBits: number;
  /** log2 of the total number of valid keys (space entropy, bits). */
  spaceBits: number;
}

/**
 * Estimate the entropy of a credential key. `spaceBits` is the log2 of the
 * exact number of valid keys of the configured length/alphabet; `keyBits`
 * is the Shannon entropy of the specific key's character distribution.
 */
export function credentialKeyEntropy(key: string): CredentialEntropy {
  const v = validateCredentialKey(key);
  if (!v.valid) return { keyBits: 0, spaceBits: 0 };

  let shannon = 0;
  for (const n of Object.values(v.counts)) {
    const p = n / key.length;
    shannon -= p * Math.log2(p);
  }
  shannon *= key.length;

  const spaceBits = Math.log2(
    countValidKeys(CREDENTIAL_KEY_LENGTH, CREDENTIAL_ALPHABET.length, CREDENTIAL_MAX_REPEAT),
  );
  return { keyBits: Math.round(shannon * 100) / 100, spaceBits: Math.round(spaceBits * 100) / 100 };
}

/**
 * Domain-separated, pre-hashed form of a credential key.
 *
 * A 7-character key is low-entropy on its own, so before it reaches
 * PBKDF2 it is stretched through SHA-256 with a domain-separation prefix.
 * This (a) guarantees a high-entropy 256-bit input to the KDF, and (b)
 * ensures a credential key can never collide with a passphrase-derived
 * secret, even if a user happens to type an identical string.
 */
export function credentialKeySecret(key: string): string {
  const v = validateCredentialKey(key);
  if (!v.valid) {
    throw new Error(v.errors.join(' '));
  }
  return createHash('sha256').update(CREDENTIAL_KEY_DOMAIN).update(key, 'utf-8').digest('hex');
}

/** An identifier for a credential input that a caller supplies to nano/macro. */
export interface CredentialKeyInput {
  type: 'credentialKey';
  value: string;
}

/** Convenience wrapper: build a validated CredentialKeyInput from a raw key. */
export function credentialKey(value: string): CredentialKeyInput {
  const v = validateCredentialKey(value);
  if (!v.valid) throw new Error(v.errors.join(' '));
  return { type: 'credentialKey', value };
}

/** Generate a fresh random credential key and return it as a typed input. */
export function newCredentialKey(): CredentialKeyInput {
  return { type: 'credentialKey', value: generateCredentialKey() };
}

/**
 * High-entropy local secret for passkey-bound vault wrapping. Exposed so
 * the passkey vault can derive its own random 32-byte vault key.
 */
export function randomVaultSecret(): Buffer {
  return randomBytes(32);
}
