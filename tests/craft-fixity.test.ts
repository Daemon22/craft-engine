import {
  computeFixityRecord,
  verifyFixityRecord,
  serializeFixityRecord,
  parseFixityRecord,
  fixitySidecarPath,
} from '../src/lib/craft/fixity';

describe('lib/craft: fixity records', () => {
  test('a freshly-recorded fixity matches the same buffer', () => {
    const data = Buffer.from('some package bytes '.repeat(50));
    const record = computeFixityRecord(data);
    const result = verifyFixityRecord(data, record);
    expect(result.ok).toBe(true);
  });

  test('detects a single-byte change (simulated bitrot)', () => {
    const data = Buffer.from('some package bytes '.repeat(50));
    const record = computeFixityRecord(data);
    const corrupted = Buffer.from(data);
    corrupted[10] ^= 0xff;
    const result = verifyFixityRecord(corrupted, record);
    expect(result.ok).toBe(false);
  });

  test('detects a truncated file', () => {
    const data = Buffer.from('some package bytes '.repeat(50));
    const record = computeFixityRecord(data);
    const truncated = data.subarray(0, data.length - 10);
    const result = verifyFixityRecord(truncated, record);
    expect(result.ok).toBe(false);
  });

  test('serialize/parse round-trips exactly', () => {
    const data = Buffer.from('round trip test data');
    const record = computeFixityRecord(data);
    const text = serializeFixityRecord(record);
    const parsed = parseFixityRecord(text);
    expect(parsed.sha256).toBe(record.sha256);
    expect(parsed.size).toBe(record.size);
  });

  test('parseFixityRecord rejects malformed input', () => {
    expect(() => parseFixityRecord('not json')).toThrow();
    expect(() => parseFixityRecord('{"foo": "bar"}')).toThrow();
  });

  test('sidecar path convention', () => {
    expect(fixitySidecarPath('/vault/notes.txt.craft')).toBe('/vault/notes.txt.craft.fixity.json');
  });
});
