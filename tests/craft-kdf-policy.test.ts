import { describe, expect, test } from 'vitest';
import { CraftTier, getFeatures } from '../src/lib/craft/features';
import { selfTest } from '../src/lib/craft/self-test';
import { PBKDF2_ITERATIONS } from '../src/lib/craft/types';

describe('KDF policy', () => {
  test.each(Object.values(CraftTier))('%s reports the iterations used by the archive codec', async (tier) => {
    expect(getFeatures(tier).kdfIterations).toBe(PBKDF2_ITERATIONS);
    expect((await selfTest(tier)).securityFloor).toBe(PBKDF2_ITERATIONS);
  });
});
