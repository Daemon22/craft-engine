import { describe, expect, it, vi } from 'vitest';
import { createCraftHttpAdapter, CRAFT_ARTIFACT_ICONS } from '../src/lib/craft';

const PASSPHRASE = 'adapter-test-passphrase-2026';

function formRequest(file: File, passphrase = PASSPHRASE): Request {
  const form = new FormData();
  form.set('file', file);
  form.set('passphrase', passphrase);
  return new Request('http://craft.test/adapter', { method: 'POST', body: form });
}

describe('framework-neutral Craft HTTP adapter', () => {
  it('creates a production `.craft` response with combined icon metadata and restores it', async () => {
    const adapter = createCraftHttpAdapter({ corsOrigin: 'https://aruk.example' });
    const source = 'Adapter integration sample — restored byte-for-byte.';
    const created = await adapter.create(formRequest(new File([source], 'adapter-sample.txt', { type: 'text/plain' })));

    expect(created.status).toBe(200);
    expect(created.headers.get('content-disposition')).toContain('adapter-sample.txt.craft');
    expect(created.headers.get('x-craft-artifact-kind')).toBe(CRAFT_ARTIFACT_ICONS.compressionAndEncryption.kind);
    expect(created.headers.get('x-craft-icon')).toBe(CRAFT_ARTIFACT_ICONS.compressionAndEncryption.publicPath);
    expect(created.headers.get('access-control-allow-origin')).toBe('https://aruk.example');

    const archive = await created.arrayBuffer();
    const restored = await adapter.restore(formRequest(new File([archive], 'adapter-sample.txt.craft')));
    expect(restored.status).toBe(200);
    expect(restored.headers.get('x-craft-integrity-verified')).toBe('true');
    expect(restored.headers.get('content-disposition')).toContain('adapter-sample.txt');
    expect(await restored.text()).toBe(source);
  });

  it('returns preflight headers and does not enable cross-origin access by default', () => {
    const preflight = createCraftHttpAdapter().options();
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-methods')).toBe('POST, OPTIONS');
    expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('rejects requests without a file and files over the configured size cap', async () => {
    const adapter = createCraftHttpAdapter({ maxFileSizeBytes: 4 });
    const emptyForm = new FormData();
    emptyForm.set('passphrase', PASSPHRASE);
    const missingFile = await adapter.create(new Request('http://craft.test/adapter', { method: 'POST', body: emptyForm }));
    expect(missingFile.status).toBe(400);
    expect((await missingFile.json()).error).toContain('No file');

    const oversized = await adapter.create(formRequest(new File(['12345'], 'large.txt')));
    expect(oversized.status).toBe(413);
  });

  it('rejects non-POST operations with 405', async () => {
    const response = await createCraftHttpAdapter().create(new Request('http://craft.test/adapter', { method: 'GET' }));
    expect(response.status).toBe(405);
    expect((await response.json()).error).toContain('POST');
  });

  it('does not log uploaded content or passphrases when restore fails', async () => {
    const adapter = createCraftHttpAdapter();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const sensitivePayload = 'private archive bytes that must not appear in logs';
    let logLines: string[] = [];
    try {
      const response = await adapter.restore(formRequest(
        new File([sensitivePayload], 'broken.craft'),
        'sensitive-passphrase-never-log-this',
      ));
      expect(response.status).toBeGreaterThanOrEqual(400);
      logLines = errorSpy.mock.calls.map(args => args.join(' '));
    } finally {
      errorSpy.mockRestore();
    }

    expect(logLines).toHaveLength(1);
    const logLine = logLines.join(' ');
    expect(logLine).toMatch(/\[Craft HTTP adapter: restore\] request [0-9a-f-]+ failed\./);
    expect(logLine).not.toContain(sensitivePayload);
    expect(logLine).not.toContain('sensitive-passphrase-never-log-this');
  });
});
