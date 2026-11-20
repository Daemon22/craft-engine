import { randomUUID } from 'node:crypto';
import { macro } from './macro';
import { nano } from './nano';
import { CRAFT_ARTIFACT_ICONS } from './artifact-icons';
import { contentDispositionAttachment } from '../http';

const DEFAULT_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;
const CORS_METHODS = 'POST, OPTIONS';
const CORS_HEADERS = 'Content-Type';
const CORS_EXPOSE_HEADERS = 'X-Craft-Request-Id, X-Craft-Original-Size, X-Craft-Crafted-Size, X-Craft-Compressed-Size, X-Craft-Compression-Ratio, X-Craft-Space-Saved, X-Craft-Space-Saved-Percent, X-Craft-Checksum, X-Craft-Mode, X-Craft-Strategy, X-Craft-Version, X-Craft-Artifact-Kind, X-Craft-Icon, X-Craft-Benchmarks, X-Craft-Processing-Time, X-Craft-Restored-Size, X-Craft-Original-Name, X-Craft-Integrity-Verified';

export interface CraftHttpAdapterOptions {
  /** Maximum uploaded file size. The host server should enforce its own request-body limit too. */
  maxFileSizeBytes?: number;
  /** Set an explicit origin to enable CORS. Omit to leave CORS disabled by default. */
  corsOrigin?: string;
}

export interface CraftHttpAdapter {
  /** Handle a multipart/form-data request with `file` and `passphrase` fields; returns a compressed+encrypted `.craft` response. */
  create(request: Request): Promise<Response>;
  /** Handle a multipart/form-data request with `file` and `passphrase` fields; returns the restored file. */
  restore(request: Request): Promise<Response>;
  /** Return the preflight response for either operation. */
  options(): Response;
}

/**
 * Create framework-neutral HTTP handlers built on the standard Fetch Request/Response APIs.
 * Mount `create`, `restore`, and `options` in a server or framework adapter of your choice.
 * The host application remains responsible for authentication, rate limiting, and request-body limits.
 */
export function createCraftHttpAdapter(options: CraftHttpAdapterOptions = {}): CraftHttpAdapter {
  const maxFileSizeBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  if (!Number.isSafeInteger(maxFileSizeBytes) || maxFileSizeBytes <= 0) {
    throw new RangeError('maxFileSizeBytes must be a positive safe integer.');
  }

  const baseHeaders: Record<string, string> = {
    'Access-Control-Allow-Methods': CORS_METHODS,
    'Access-Control-Allow-Headers': CORS_HEADERS,
    'Access-Control-Expose-Headers': CORS_EXPOSE_HEADERS,
  };
  if (options.corsOrigin) baseHeaders['Access-Control-Allow-Origin'] = options.corsOrigin;

  const makeJson = (body: { error: string }, status: number, requestId: string, startTime: number) =>
    Response.json(body, {
      status,
      headers: {
        ...baseHeaders,
        'Content-Type': 'application/json; charset=utf-8',
        'X-Craft-Request-Id': requestId,
        'X-Craft-Processing-Time': Math.round(performance.now() - startTime).toString(),
      },
    });

  const methodNotAllowed = (request: Request, operation: string) => {
    const requestId = randomUUID();
    const startTime = performance.now();
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: baseHeaders });
    return makeJson({ error: `Use POST to ${operation} a Craft file.` }, 405, requestId, startTime);
  };

  const processRequest = async (request: Request, operation: 'create' | 'restore'): Promise<Response> => {
    if (request.method !== 'POST') return methodNotAllowed(request, operation);

    const requestId = randomUUID();
    const startTime = performance.now();
    const operationName = operation === 'create' ? 'create an archive' : 'restore an archive';

    try {
      const declaredLength = Number(request.headers.get('content-length'));
      // Allow a modest amount of multipart overhead; the parsed file size is checked below.
      if (Number.isFinite(declaredLength) && declaredLength > maxFileSizeBytes + 1024 * 1024) {
        return makeJson({ error: `Request exceeds the maximum allowed file size of ${maxFileSizeBytes} bytes.` }, 413, requestId, startTime);
      }

      const formData = await request.formData();
      const filePart = formData.get('file');
      const passphrasePart = formData.get('passphrase');

      if (!filePart || typeof filePart === 'string') {
        return makeJson({ error: 'No file provided. Add a file field to the multipart form.' }, 400, requestId, startTime);
      }
      if (typeof passphrasePart !== 'string' || passphrasePart.length < 12) {
        return makeJson({ error: 'Passphrase must be at least 12 characters.' }, 400, requestId, startTime);
      }
      if (filePart.size > maxFileSizeBytes) {
        return makeJson({ error: `File size exceeds the maximum allowed size of ${maxFileSizeBytes} bytes.` }, 413, requestId, startTime);
      }

      const data = Buffer.from(await filePart.arrayBuffer());
      const originalName = filePart.name.split(/[\\/]/).pop() || 'upload';
      if (operation === 'create') {
        const result = await nano(data, originalName, filePart.type || 'application/octet-stream', passphrasePart, {
          compressionMode: '7fold',
        });
        const outputName = originalName.toLowerCase().endsWith('.craft')
          ? originalName
          : `${originalName}.craft`;
        const benchmarks = result.strategyBenchmarks ? JSON.stringify(result.strategyBenchmarks) : '';

        return new Response(new Uint8Array(result.buffer), {
          status: 200,
          headers: {
            ...baseHeaders,
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': contentDispositionAttachment(outputName),
            'X-Craft-Original-Size': result.metadata.originalSize.toString(),
            'X-Craft-Crafted-Size': result.buffer.length.toString(),
            'X-Craft-Compressed-Size': result.metadata.compressedSize.toString(),
            'X-Craft-Compression-Ratio': result.compressionRatio.toFixed(4),
            'X-Craft-Space-Saved': result.spaceSaved.toString(),
            'X-Craft-Space-Saved-Percent': result.spaceSavedPercent.toFixed(2),
            'X-Craft-Checksum': result.metadata.originalChecksum,
            'X-Craft-Mode': result.metadata.compressionMode,
            'X-Craft-Strategy': result.metadata.compressionStrategyName || 'brotli',
            'X-Craft-Version': result.metadata.version.toString(),
            'X-Craft-Artifact-Kind': CRAFT_ARTIFACT_ICONS.compressionAndEncryption.kind,
            'X-Craft-Icon': CRAFT_ARTIFACT_ICONS.compressionAndEncryption.publicPath,
            'X-Craft-Benchmarks': benchmarks,
            'X-Craft-Processing-Time': Math.round(performance.now() - startTime).toString(),
            'X-Craft-Request-Id': requestId,
          },
        });
      }

      const result = await macro(data, passphrasePart);
      return new Response(new Uint8Array(result.buffer), {
        status: 200,
        headers: {
          ...baseHeaders,
          'Content-Type': result.metadata.originalMime || 'application/octet-stream',
          'Content-Disposition': contentDispositionAttachment(result.metadata.originalName),
          'X-Craft-Restored-Size': result.buffer.length.toString(),
          'X-Craft-Original-Name': encodeURIComponent(result.metadata.originalName),
          'X-Craft-Integrity-Verified': result.integrityVerified.toString(),
          'X-Craft-Checksum': result.metadata.originalChecksum,
          'X-Craft-Mode': result.metadata.compressionMode || 'brotli',
          'X-Craft-Strategy': result.metadata.compressionStrategyName || 'brotli',
          'X-Craft-Processing-Time': Math.round(performance.now() - startTime).toString(),
          'X-Craft-Request-Id': requestId,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : `An unknown error occurred while attempting to ${operationName}.`;
      // Log only the correlation id and operation. Error objects can carry details about
      // uploaded content or cryptographic state and should not be copied to server logs.
      console.error(`[Craft HTTP adapter: ${operation}] request ${requestId} failed.`);
      if (operation === 'restore' && message.includes('INTEGRITY FAILURE')) {
        return makeJson({ error: 'Integrity verification failed. The restored data does not match the original; the archive may be corrupted.' }, 422, requestId, startTime);
      }
      if (operation === 'restore' && /auth tag|EVP_DecryptFinal|Unsupported state|Unsupported/i.test(message)) {
        return makeJson({ error: 'Decryption failed — the passphrase may be incorrect.' }, 401, requestId, startTime);
      }
      if (error instanceof TypeError || message.includes('multipart')) {
        return makeJson({ error: 'Invalid request body. Expected multipart/form-data with file and passphrase fields.' }, 400, requestId, startTime);
      }
      return makeJson({ error: message }, 500, requestId, startTime);
    }
  };

  return {
    create: (request) => processRequest(request, 'create'),
    restore: (request) => processRequest(request, 'restore'),
    options: () => new Response(null, { status: 204, headers: baseHeaders }),
  };
}
