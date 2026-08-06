/**
 * @craft/http — small shared helpers for building HTTP responses.
 */

/**
 * Build a `Content-Disposition: attachment` header value that's safe for
 * ANY filename, including ones with quotes, backslashes, or non-ASCII
 * characters (accents, CJK, emoji, etc).
 *
 * Two bugs this fixes (both previously present in the nano/macro API
 * routes, which built this header via a raw template string):
 *
 * 1. An unescaped `"` in the filename (e.g. `he said "hi".txt`) breaks
 *    out of the quoted-string early, producing a header most HTTP
 *    clients can't parse correctly.
 * 2. Any character outside ISO-8859-1 (any non-Latin filename — CJK,
 *    Cyrillic, emoji, even plain accented Latin like "café.txt") makes
 *    the underlying Headers/fetch implementation throw a TypeError when
 *    the header is set ("character ... is greater than 255"), which
 *    surfaces as an opaque 500 error to the caller after the file was
 *    already successfully crafted/restored.
 *
 * Fix: sanitize the plain `filename=` fallback to safe ASCII, and carry
 * the real name via the RFC 5987/6266 `filename*=UTF-8''<percent-encoded>`
 * extended parameter, which every modern HTTP client understands and
 * which has no byte-range restriction.
 */
export function contentDispositionAttachment(filename: string): string {
  const safeName = filename && filename.trim().length > 0 ? filename : 'download';

  // ASCII fallback for older clients that ignore filename*: strip quotes/
  // backslashes (would break the quoted-string) and anything outside the
  // printable ISO-8859-1 range Headers can encode without throwing.
  const asciiFallback = safeName
    .replace(/[\\"]/g, '_')
    .replace(/[^\x20-\x7E]/g, '_')
    .trim() || 'download';

  const encoded = encodeURIComponent(safeName)
    // encodeURIComponent leaves these unescaped; RFC 5987 requires them encoded too
    .replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}
