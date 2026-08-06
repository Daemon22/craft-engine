/**
 * Golden fixture — backward compatibility lock.
 *
 * This is a real .craft package, encoded once (with the code as of this
 * commit) and frozen here as a base64 fixture. It exists to catch future
 * changes that accidentally break decoding of packages people already
 * have on disk — the kind of regression that wouldn't show up in normal
 * round-trip tests (which always encode AND decode with whatever the
 * current code happens to be) but would be exactly the "nothing lost"
 * failure mode for a real vault: someone's months-old .craft file
 * suddenly refusing to open after an unrelated update.
 *
 * If this test ever needs to change, that's a deliberate breaking format
 * change — treat it as a decision to make consciously (bump CRAFT_VERSION,
 * document it, decide on a migration path), not as "just regenerate the
 * fixture and move on."
 */
import { macro } from '../src/lib/craft/macro';

const GOLDEN_PASSPHRASE = 'golden-fixture-passphrase-2026';
const GOLDEN_ORIGINAL_TEXT =
  'CRAFT golden fixture — this text must always decode correctly, forever, with the fixed passphrase below.';

// Generated with nano() at the time this fixture was created. Do not
// regenerate casually — see the file header above.
const GOLDEN_PACKAGE_BASE64 =
  'Q1JBRlQxA4AAAY6IEm5O20hyyMQOeCx+c8IMtUR3WtH2QOS4PXNvkhxYrOkXKzbxKXqT3DU7coQv' +
  'jpGSUfYlFtSTT3kyFRJClLOkuOhh+sTl9Box1cmbZAySND+7ylpHG2IJR+14DMgnJfj1lxAzgWnr' +
  'qPzMQiDLY5yGw7P2tTLACiTPZppvwld5/PVNdV/ktVWsEhGya/xE5eoA3xLXjJ5nSovsJoJMY/iP' +
  'gYTr2GeQEqC1IpaE/UzUu0GfWRIhiKNsblldjYAD/elAz5VP41QTdhqftWwz6FNT6cM3C7cFY7hJ' +
  'M1DMJAhB0CDFi61OHTf0xJW0MCVGk0GLIQBrpQI4Z13UyOTe7IYYE1poLKfsuijckYnSa0uYI0s6' +
  'Ohl2h7FuHQsikZ6PDHgUIqqkmaDYVGKc3SksYnpjhldACI9PSYLnmKeUiCg56BRem9Ab0LHRZuMy' +
  'eo/IuFLdeW9YcDhvLOzV0r+4cfSVD0lngeUhfqiM+G4ayvBSdVu9iIDd/ijwuoEPFK8Cfq4yL1mX' +
  'yEFIvK4/VZJPuf0IqWDgCAHWBnNre1JJ4AD/8Lj/k/obGYkolFRzsqsGcXcFmUSLPHjb8tnjRrT0' +
  'Caaf+E2wWzSeRxy+8gP5VYU4dmdHV+R1t27cd1/ZT79ikMxnMP50B4CzsUqmox4G1INsIxLhkgg' +
  'QjEpPHBWopjxGuSXNeLE5YzWYP5ElZS8hkP/e54rRDOf2';

describe('lib/craft: golden backward-compatibility fixture', () => {
  test('a previously-encoded package still decodes correctly with the current code', () => {
    const packageBuffer = Buffer.from(GOLDEN_PACKAGE_BASE64, 'base64');
    const result = macro(packageBuffer, GOLDEN_PASSPHRASE);
    expect(result.buffer.toString('utf-8')).toBe(GOLDEN_ORIGINAL_TEXT);
    expect(result.integrityVerified).toBe(true);
    expect(result.metadata.originalName).toBe('golden.txt');
  });

  test('wrong passphrase against the golden fixture still fails safely', () => {
    const packageBuffer = Buffer.from(GOLDEN_PACKAGE_BASE64, 'base64');
    expect(() => macro(packageBuffer, 'definitely-the-wrong-passphrase')).toThrow();
  });
});
