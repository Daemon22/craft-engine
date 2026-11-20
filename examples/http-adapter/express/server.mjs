import express from 'express';
import { Readable } from 'node:stream';
import { createCraftHttpAdapter } from 'craft-engine/lib/craft/http-adapter';

const app = express();
const port = Number(process.env.PORT ?? 3000);
const maxFileSizeBytes = 100 * 1024 * 1024; // 100 MiB
const maxMultipartBodyBytes = maxFileSizeBytes + 1024 * 1024; // allow up to 1 MiB of multipart overhead

const craft = createCraftHttpAdapter({ maxFileSizeBytes });
app.disable('x-powered-by');

// Mount the host application's real auth middleware here; it should set req.user.
// Example: app.use('/api', yourSessionOrJwtMiddleware);

// The adapter parses multipart/form-data itself. Preserve the raw body rather than
// using multer or express.json() on these endpoints. This route-scoped parser also
// caps chunked uploads that do not include Content-Length.
const boundedRawBody = express.raw({
  type: () => true,
  limit: maxMultipartBodyBytes,
});

// Example fail-closed hook. Mount your real session/JWT middleware before these
// routes so it establishes req.user; replace this check to match your app.
function requireAuthenticatedUser(req, res, next) {
  if (!req.user?.id) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  return next();
}

function toFetchRequest(req) {
  const headers = new Headers();
  const contentType = req.get('content-type');
  const contentLength = req.get('content-length');

  if (contentType) headers.set('content-type', contentType);
  if (contentLength) headers.set('content-length', contentLength);

  return new Request(new URL(req.originalUrl, 'http://localhost'), {
    method: req.method,
    headers,
    body: Buffer.isBuffer(req.body) ? req.body : undefined,
  });
}

function sendFetchResponse(res, fetchResponse) {
  fetchResponse.headers.forEach((value, name) => res.setHeader(name, value));
  res.status(fetchResponse.status);

  if (!fetchResponse.body) {
    res.end();
    return;
  }

  Readable.fromWeb(fetchResponse.body)
    .on('error', (error) => res.destroy(error))
    .pipe(res);
}

function forwardToCraft(handler) {
  return async (req, res, next) => {
    try {
      const fetchRequest = toFetchRequest(req);
      const fetchResponse = await handler(fetchRequest);
      sendFetchResponse(res, fetchResponse);
    } catch (error) {
      next(error);
    }
  };
}

// Same-origin example. The adapter supplies its own OPTIONS response headers.
// For cross-origin browser clients, see the CORS notes in README.md.
app.options('/api/craft', (_req, res) => sendFetchResponse(res, craft.options()));
app.options('/api/uncraft', (_req, res) => sendFetchResponse(res, craft.options()));

// Put your per-user/IP upload rate limiter after authentication and before
// boundedRawBody. Do not mount a body parser that consumes these multipart bodies.
app.post(
  '/api/craft',
  requireAuthenticatedUser,
  boundedRawBody,
  forwardToCraft(craft.create),
);
app.post(
  '/api/uncraft',
  requireAuthenticatedUser,
  boundedRawBody,
  forwardToCraft(craft.restore),
);

// Express/body-parser reports an oversized raw body as entity.too.large.
app.use((error, _req, res, next) => {
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Upload exceeds the configured request-body limit.' });
  }
  if (res.headersSent) return next(error);
  console.error('Express request failed:', error);
  return res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, () => {
  console.log(`Craft Engine Express example listening on http://localhost:${port}`);
});
