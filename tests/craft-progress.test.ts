import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { macro, nano } from '../src/lib/craft';
import { CraftProgressObserverError, jsonlProgressObserver } from '../src/lib/craft/progress';

const PASSPHRASE = 'craft-progress-test-passphrase';
const DATA = Buffer.from('process monitoring should expose progress, not payloads');
const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});

describe('CRAFT progress monitoring', () => {
  it('reports safe pack and self-verification stages without disclosing secrets or content', async () => {
    const events: Array<Record<string, unknown>> = [];
    const result = await nano(DATA, 'private-document.txt', 'text/plain', PASSPHRASE, {
      operationId: 'pack-run-1',
      onProgress: event => { events.push(event as unknown as Record<string, unknown>); },
    });

    expect(result.buffer.length).toBeGreaterThan(0);
    expect(events[0]).toMatchObject({ operation_id: 'pack-run-1', operation: 'nano', step: 'operation', status: 'started' });
    expect(events.at(-1)).toMatchObject({ operation_id: 'pack-run-1', operation: 'nano', step: 'operation', status: 'completed' });
    expect(events.some(event => event.step === 'compress' && event.status === 'completed')).toBe(true);
    expect(events.some(event => event.step === 'derive_keys' && event.status === 'completed')).toBe(true);
    expect(events.some(event => event.step === 'encrypt_payload' && event.status === 'completed')).toBe(true);
    expect(events.some(event => event.step === 'self_verify.verify_integrity' && event.status === 'completed')).toBe(true);
    expect(JSON.stringify(events)).not.toContain(PASSPHRASE);
    expect(JSON.stringify(events)).not.toContain(DATA.toString());
    expect(JSON.stringify(events)).not.toContain('private-document.txt');
  });

  it('can be observed by a host process and reports unpack integrity checks', async () => {
    const events: Array<Record<string, unknown>> = [];
    const packaged = await nano(DATA, 'document.txt', 'text/plain', PASSPHRASE);
    const restored = await macro(packaged.buffer, PASSPHRASE, {
      operationId: 'restore-run-1',
      onProgress: event => { events.push(event as unknown as Record<string, unknown>); },
    });

    expect(restored.buffer).toEqual(DATA);
    expect(events.map(event => event.step)).toContain('validate_and_parse_package');
    expect(events.map(event => event.step)).toContain('decrypt_payload');
    expect(events.map(event => event.step)).toContain('decompress');
    expect(events).toContainEqual(expect.objectContaining({
      operation_id: 'restore-run-1',
      operation: 'macro',
      step: 'verify_integrity',
      status: 'completed',
    }));
    expect(JSON.stringify(events)).not.toContain(PASSPHRASE);
    expect(JSON.stringify(events)).not.toContain(DATA.toString());
  });

  it('records a failed stage without putting the raw error or passphrase in the event', async () => {
    const events: Array<Record<string, unknown>> = [];
    const packaged = await nano(DATA, 'document.txt', 'text/plain', PASSPHRASE);

    await expect(macro(packaged.buffer, 'wrong-craft-progress-passphrase', {
      onProgress: event => { events.push(event as unknown as Record<string, unknown>); },
    })).rejects.toThrow();

    const failed = events.find(event => event.status === 'failed');
    expect(failed).toBeDefined();
    expect(JSON.stringify(events)).not.toContain(PASSPHRASE);
    expect(JSON.stringify(events)).not.toContain('wrong-craft-progress-passphrase');
    expect(JSON.stringify(events)).not.toContain('incorrect passphrase');
  });

  it('keeps self-verification enabled by default and exposes the explicit opt-out', async () => {
    const verified: string[] = [];
    const skipped: string[] = [];
    await nano(DATA, 'document.txt', 'text/plain', PASSPHRASE, {
      onProgress: event => { verified.push(event.step); },
    });
    await nano(DATA, 'document.txt', 'text/plain', PASSPHRASE, {
      verify: false,
      onProgress: event => { skipped.push(event.step); },
    });

    expect(verified).toContain('self_verify');
    expect(verified).toContain('self_verify.verify_integrity');
    expect(skipped).not.toContain('self_verify');
  });

  it('writes a JSONL stream suitable for an external process monitor', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'craft-progress-'));
    tempDirs.push(directory);
    const eventPath = join(directory, 'events.jsonl');

    await nano(DATA, 'document.txt', 'text/plain', PASSPHRASE, {
      onProgress: jsonlProgressObserver(eventPath),
    });

    const lines = (await readFile(eventPath, 'utf8')).trim().split('\n');
    const events = lines.map(line => JSON.parse(line) as Record<string, unknown>);
    expect(events.length).toBeGreaterThan(10);
    expect(events[0]).toHaveProperty('operation_id');
    expect(events.at(-1)).toMatchObject({ step: 'operation', status: 'completed' });
  });

  it('stops if the progress observer fails rather than claiming the step was monitored', async () => {
    const observer = vi.fn(() => { throw new Error(`unexpected observer failure for ${PASSPHRASE}`); });

    await expect(nano(DATA, 'document.txt', 'text/plain', PASSPHRASE, {
      onProgress: observer,
    })).rejects.toBeInstanceOf(CraftProgressObserverError);
    expect(observer).toHaveBeenCalledTimes(1);
  });
});
