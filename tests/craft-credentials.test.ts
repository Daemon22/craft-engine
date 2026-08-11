import {
  CREDENTIAL_KEY_LENGTH,
  CREDENTIAL_MAX_REPEAT,
  CREDENTIAL_VALUES,
  CREDENTIAL_SPECIALS,
  CREDENTIAL_ALPHABET,
  validateCredentialKey,
  generateCredentialKey,
  rateCredentialKey,
  countValidKeys,
  credentialKeyEntropy,
  credentialKeySecret,
  credentialKey,
  newCredentialKey,
  isValueChar,
  isSpecialChar,
} from '../src/lib/craft/credentials';
import { nano, macro } from '../src/lib/craft/index';

// ── Rule basics ───────────────────────────────────────────────

describe('credential key: length & alphabet', () => {
  test('constants are 7 and 3', () => {
    expect(CREDENTIAL_KEY_LENGTH).toBe(7);
    expect(CREDENTIAL_MAX_REPEAT).toBe(3);
  });

  test('alphabet contains values and specials, no overlaps', () => {
    expect(CREDENTIAL_VALUES).toMatch(/[A-Z]/);
    expect(CREDENTIAL_VALUES).toMatch(/[a-z]/);
    expect(CREDENTIAL_VALUES).toMatch(/[0-9]/);
    for (const ch of CREDENTIAL_SPECIALS) {
      expect(CREDENTIAL_VALUES).not.toContain(ch);
    }
    expect(CREDENTIAL_ALPHABET.length).toBe(CREDENTIAL_VALUES.length + CREDENTIAL_SPECIALS.length);
  });

  test('isValueChar / isSpecialChar classify correctly', () => {
    expect(isValueChar('a')).toBe(true);
    expect(isValueChar('Z')).toBe(true);
    expect(isValueChar('5')).toBe(true);
    expect(isSpecialChar('!')).toBe(true);
    expect(isSpecialChar('~')).toBe(true);
    expect(isValueChar('!')).toBe(false);
    expect(isSpecialChar('a')).toBe(false);
  });

  test('valid 7-char key passes', () => {
    const v = validateCredentialKey('Ab3!cDe');
    expect(v.valid).toBe(true);
    expect(v.errors).toEqual([]);
    expect(v.length).toBe(7);
    expect(v.distinct).toBe(7);
    expect(v.hasValue).toBe(true);
    expect(v.hasSpecial).toBe(true);
  });

  test('wrong length fails', () => {
    for (const key of ['Ab3!cD', 'Ab3!cDe1']) {
      const v = validateCredentialKey(key);
      expect(v.valid).toBe(false);
      expect(v.errors.some((e) => e.includes('exactly 7 characters'))).toBe(true);
    }
  });

  test('illegal characters fail', () => {
    // apostrophe, quote, slash, backslash are not in the allowed alphabet
    const v = validateCredentialKey(`Ab3!'cD`);
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes('not in the allowed alphabet'))).toBe(true);
  });
});

describe('credential key: max 3× repeat rule', () => {
  test('3 repeats of the same character are allowed', () => {
    expect(validateCredentialKey('AAA1234').valid).toBe(true);
    expect(validateCredentialKey('abc!def').valid).toBe(true);
  });

  test('4 repeats of the same character fail', () => {
    const v = validateCredentialKey('AAAA123');
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes('appears 4 times'))).toBe(true);
  });

  test('repeat rule applies to special characters too', () => {
    expect(validateCredentialKey('!!!abcd').valid).toBe(true); // exactly 3 specials
    const v = validateCredentialKey('!!!!123');
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes("'!' appears 4 times"))).toBe(true);
  });

  test('repeat rule applies to digits (values) too', () => {
    const v = validateCredentialKey('1111abc');
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes("'1' appears 4 times"))).toBe(true);
  });

  test('counts are reported accurately', () => {
    const v = validateCredentialKey('AAB!B!1');
    expect(v.counts['A']).toBe(2);
    expect(v.counts['B']).toBe(2);
    expect(v.counts['!']).toBe(2);
    expect(v.counts['1']).toBe(1);
    expect(v.distinct).toBe(4);
  });

  test('invalid input types are rejected', () => {
    expect(validateCredentialKey(undefined as any).valid).toBe(false);
    expect(validateCredentialKey(null as any).valid).toBe(false);
  });
});

// ── Generation ────────────────────────────────────────────────

describe('credential key: generation', () => {
  test('generated keys are always valid (1000 samples)', () => {
    for (let i = 0; i < 1000; i++) {
      const key = generateCredentialKey();
      const v = validateCredentialKey(key);
      expect(v.valid).toBe(true);
      expect(v.hasValue).toBe(true);
      expect(v.hasSpecial).toBe(true);
    }
  });

  test('generation terminates with an adversarial RNG', () => {
    const key = generateCredentialKey(() => 0);
    expect(validateCredentialKey(key).valid).toBe(true);
  });

  test('newCredentialKey returns a typed, valid input', () => {
    const input = newCredentialKey();
    expect(input.type).toBe('credentialKey');
    expect(validateCredentialKey(input.value).valid).toBe(true);
  });

  test('credentialKey() wraps and validates', () => {
    const input = credentialKey('Ab3!cDe');
    expect(input.value).toBe('Ab3!cDe');
    expect(() => credentialKey('AAAA123')).toThrow(/appears 4 times/);
  });
});

// ── Strength + entropy ────────────────────────────────────────

describe('credential key: strength & entropy', () => {
  test('invalid key rates 0 / Invalid', () => {
    const s = rateCredentialKey('AAAA123');
    expect(s.score).toBe(0);
    expect(s.rating).toBe('Invalid');
  });

  test('high-variety keys rate Strong or Fortress', () => {
    const s = rateCredentialKey('Ab3!cDe');
    expect(['Strong', 'Fortress']).toContain(s.rating);
    expect(s.score).toBeGreaterThanOrEqual(7);
  });

  test('low-variety valid keys rate Weak or Standard', () => {
    // three distinct characters, one repeated 3× — minimal variety
    const s = rateCredentialKey('AAAbbb!');
    expect(['Weak', 'Standard']).toContain(s.rating);
  });

  test('countValidKeys sanity checks', () => {
    expect(countValidKeys(1, 3, 3)).toBe(3);
    expect(countValidKeys(2, 2, 1)).toBe(2); // ab, ba
    expect(countValidKeys(2, 2, 2)).toBe(4); // all 2^2
    expect(countValidKeys(3, 2, 2)).toBe(6); // only triple repeats excluded
    expect(countValidKeys(7, 1, 3)).toBe(0); // single symbol, max 3 → impossible
  });

  test('full key-space entropy is ~45 bits for the 90-symbol alphabet', () => {
    const { spaceBits } = credentialKeyEntropy('Ab3!cDe');
    expect(spaceBits).toBeGreaterThan(44);
    expect(spaceBits).toBeLessThan(47);
  });

  test('entropy is zero for invalid keys', () => {
    expect(credentialKeyEntropy('AAAA123').keyBits).toBe(0);
    expect(credentialKeyEntropy('AAAA123').spaceBits).toBe(0);
  });
});

// ── Secret pre-hash ───────────────────────────────────────────

describe('credential key: secret pre-hash', () => {
  test('is deterministic for the same key', () => {
    expect(credentialKeySecret('Ab3!cDe')).toBe(credentialKeySecret('Ab3!cDe'));
  });

  test('differs between keys', () => {
    expect(credentialKeySecret('Ab3!cDe')).not.toBe(credentialKeySecret('Ab4!cDe'));
  });

  test('never equals the raw key', () => {
    expect(credentialKeySecret('Ab3!cDe')).not.toBe('Ab3!cDe');
    expect(credentialKeySecret('Ab3!cDe')).toMatch(/^[0-9a-f]{64}$/);
  });

  test('throws for invalid keys', () => {
    expect(() => credentialKeySecret('AAAA123')).toThrow();
  });
});

// ── End-to-end: craft + restore with a credential key ─────────

describe('credential key: nano/macro round-trip', () => {
  const data = Buffer.from('credential-key payload — craft engine test');

  test('nano with credentialKey option + macro with CredentialKeyInput round-trips', async () => {
    const crafted = await nano(data, 'doc.txt', 'text/plain', '', { credentialKey: 'Ab3!cDe' });
    const restored = await macro(crafted.buffer, { type: 'credentialKey', value: 'Ab3!cDe' });
    expect(restored.buffer.equals(data)).toBe(true);
    expect(restored.integrityVerified).toBe(true);
  });

  test('nano with credentialKey + macro with credentialKey() wrapper works too', async () => {
    const crafted = await nano(data, 'doc.txt', 'text/plain', '', { credentialKey: 'Ab3!cDe' });
    const restored = await macro(crafted.buffer, credentialKey('Ab3!cDe'));
    expect(restored.buffer.equals(data)).toBe(true);
  });

  test('a generated credential key round-trips', async () => {
    const key = generateCredentialKey();
    const crafted = await nano(data, 'doc.txt', 'text/plain', '', { credentialKey: key });
    const restored = await macro(crafted.buffer, credentialKey(key));
    expect(restored.buffer.equals(data)).toBe(true);
  });

  test('wrong credential key fails with an integrity/decrypt error', async () => {
    const crafted = await nano(data, 'doc.txt', 'text/plain', '', { credentialKey: 'Ab3!cDe' });
    await expect(macro(crafted.buffer, { type: 'credentialKey', value: 'Xb3!cDe' })).rejects.toThrow();
  });

  test('invalid credential key is rejected by nano', async () => {
    await expect(
      nano(data, 'doc.txt', 'text/plain', '', { credentialKey: 'AAAA123' }),
    ).rejects.toThrow(/appears 4 times/);
  });

  test('a credential-key package cannot be restored with a passphrase', async () => {
    const crafted = await nano(data, 'doc.txt', 'text/plain', '', { credentialKey: 'Ab3!cDe' });
    await expect(macro(crafted.buffer, 'correct-horse-battery')).rejects.toThrow();
  });

  test('a passphrase package still cannot be restored with a credential key', async () => {
    const crafted = await nano(data, 'doc.txt', 'text/plain', 'correct-horse-battery');
    await expect(macro(crafted.buffer, credentialKey('Ab3!cDe'))).rejects.toThrow();
  });

  test('passphrase behaviour is unchanged (≥12 chars required)', async () => {
    await expect(nano(data, 'doc.txt', 'text/plain', 'short')).rejects.toThrow(/at least 12/);
    const crafted = await nano(data, 'doc.txt', 'text/plain', 'correct-horse-battery');
    const restored = await macro(crafted.buffer, 'correct-horse-battery');
    expect(restored.buffer.equals(data)).toBe(true);
  });
});
