# Craft Engine HTTP adapter with Express

This example mounts Craft Engine’s framework-neutral Fetch API adapter on an Express server. It uses the public `craft-engine/lib/craft/http-adapter` export and keeps the adapter’s multipart parser in control of the form data.

## Requirements and setup

Use Node.js **22.15 or newer**, matching the Craft Engine package engine requirement, plus an installed Craft Engine package. If the package is available in your registry, install it with Express in the application directory:

```bash
npm install express craft-engine
```

If it is not yet available from your registry, make the repository available through your monorepo’s workspace configuration or a local `file:` dependency; the import path in the example remains the same.

Copy [`server.mjs`](./server.mjs) into that app and run it with:

```bash
PORT=3000 node server.mjs
```

The example intentionally fails closed: `requireAuthenticatedUser` expects the application’s existing authentication middleware to set `req.user.id`. Mount your real session/JWT middleware before the Craft routes (for example, `app.use('/api', yourSessionMiddleware)`), or replace the stub with the authentication check used by your app. Add a per-user/IP upload rate limiter after authentication and before reading the body. Until that middleware is connected, the sample returns `401` by design.

## Routes and form fields

| Route | Method | Multipart fields | Result |
| --- | --- | --- | --- |
| `/api/craft` | `POST` | `file`, `passphrase` | Compressed-and-encrypted production `.craft` archive |
| `/api/uncraft` | `POST` | `file`, `passphrase` | Restored original file |
| Either route | `OPTIONS` | — | Adapter preflight response |

The passphrase must be at least 12 characters. The create response is binary and includes a `Content-Disposition` filename ending in `.craft`. The restore response uses the archive’s original filename and MIME type where available. The adapter also returns metadata headers such as `X-Craft-Artifact-Kind`, `X-Craft-Icon`, `X-Craft-Checksum`, `X-Craft-Strategy`, `X-Craft-Processing-Time`, and `X-Craft-Integrity-Verified` (restore only).

## Try the endpoints

Use a strong passphrase from a secret manager or environment variable; avoid putting real secrets directly in shell history or application logs. These requests must also carry whatever session cookie or authorization credential your authentication middleware expects.

```bash
export CRAFT_PASSPHRASE='replace-this-with-a-strong-secret'

curl --fail-with-body -sS \
  -F 'file=@./report.pdf' \
  -F "passphrase=${CRAFT_PASSPHRASE}" \
  http://localhost:3000/api/craft \
  --output ./report.pdf.craft

curl --fail-with-body -sS \
  -F 'file=@./report.pdf.craft' \
  -F "passphrase=${CRAFT_PASSPHRASE}" \
  http://localhost:3000/api/uncraft \
  --output ./report-restored.pdf
```

For browser clients, send a `FormData` body with fields named exactly `file` and `passphrase`; let the browser set the multipart `Content-Type` boundary rather than setting that header manually.

## Why the Express bridge uses `express.raw`

The Craft adapter consumes a standard Fetch `Request` and calls `request.formData()`. The example uses route-scoped `express.raw()` to preserve the original multipart bytes, then constructs a Fetch `Request` with the original `Content-Type` (including its boundary). Do **not** put Multer, `express.json()`, `express.urlencoded()`, or another body parser that consumes these routes’ bodies ahead of this bridge; once parsed, the raw multipart stream cannot be reconstructed reliably.

The adapter defaults to a 100 MiB file limit. The example configures that same limit and caps the raw request at 101 MiB to allow up to 1 MiB of multipart overhead. The application and reverse proxy should enforce matching or lower body-size limits. The adapter currently uses `request.formData()` and buffers the file for processing; it is not a constant-memory, multi-gigabyte upload endpoint. Lower the cap or use the library’s streaming APIs for larger workloads.

## CORS and deployment

The example is intended for same-origin use and leaves `corsOrigin` unset. The adapter’s built-in CORS handling supports an explicitly configured origin and the `POST`/`OPTIONS` methods, but its allowed request headers are limited to `Content-Type`; it does not enable credentialed CORS. For cross-origin browser use with cookies, bearer authorization, or additional headers, implement and test the host application’s complete CORS policy at the Express layer (including preflight, exact allowed origins, credentials if needed, and `Vary: Origin`). Do not use `corsOrigin: '*'` for credentialed requests.

In production:

- Serve the endpoints only over HTTPS.
- Authenticate and authorize each upload/restore request; avoid logging passphrases, multipart bodies, or sensitive filenames.
- Rate-limit per user and, where appropriate, per IP; add concurrency controls for CPU- and memory-intensive archive operations.
- Apply request-size limits at Express and the ingress/proxy, and set suitable request/idle timeouts.
- Store secrets outside source control and prefer a secrets manager or a protected passphrase-entry flow.
- Treat `X-Craft-Icon` as display metadata, not a security signal. It points to `/craft-icons/compressed-encrypted.webp`; serve/copy the package’s optimized icon assets if the host app wants to display it.

## Error responses

The adapter returns JSON errors for invalid multipart requests or short passphrases (`400`), oversized requests/files (`413`), failed decryption (`401`), integrity failure (`422`), unsupported methods (`405`), and unexpected processing errors (`500`). Express’s raw-body parser can reject an oversized request before the adapter runs; the example maps that parser error to `413` as well.
