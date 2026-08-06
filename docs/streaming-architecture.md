# CRAFT Streaming Architecture (v4 — Constant-Memory Streaming)

> **Status:** Reference implementation. `nano()` / `macro()` (v1–v3) are the gold
> standard and are intentionally left **untouched**. This document describes a
> **second execution path** — `nanoStream()` / `macroStream()` — that adds
> constant-memory, chunked processing for arbitrarily large files.
>
> See [`chunk-format.md`](./chunk-format.md) for the exact on-disk layout.

## 1. Goals

| Property | In-memory (`nano`/`macro`, v1–v3) | Streaming (`nanoStream`/`macroStream`, v4) |
|---|---|---|
| Memory (peak RAM) | ≈ `3 × input size` | **≈ constant** (chunk size + small buffers + minimal metadata) |
| Input handling | Whole file in a `Buffer` | `fs.createReadStream` / `Readable` (fixed-size chunks) |
| Output handling | Single `Buffer` | `fs.createWriteStream` / `Writable` (streaming, atomic temp+rename) |
| Archive format | v1/v2/v3 single-blob | **v4** chunked (backward compatible) |
| Independent chunks | No (one AES-GCM tag for the whole blob) | **Yes** (per-chunk IV + auth tag) |
| Failure recovery | Atomic `safeWriteFile` temp+rename | Atomic temp+rename **+** temp chunk-file cleanup |
| Corruption detection | AES-GCM tag + SHA-256 | **Per-chunk** AES-GCM tag **+** per-chunk compress check **+** final SHA-256 **+** byte-count |
| Parallelism | None | Per-chunk independence enables future parallel encode/decode |

## 2. Non-goals (explicitly out of scope)

- Replacing `nano()` / `macro()` or the v1–v3 format.
- Running the 12-strategy adaptive selector (`compress7`) on the hot path — it
  is fundamentally *whole-file* (it must hold all candidate outputs
  simultaneously). The streaming path uses a **single, streaming-native
  strategy** chosen per archive (see §4). The streaming archive is therefore a
  *different* archive byte-for-byte than `nano()` would produce, but it always
  **restores to bit-identical original bytes** (the validation contract).

## 3. Design constraints

1. **Never break existing archives.** v1/v2/v3 readers (`macro`, `peekMetadata`)
   are unchanged and continue to read every legacy archive unchanged.
2. **Security parity.** AES-256-GCM, PBKDF2-SHA256 (600 000 iterations), SHA-256
   integrity, authentication, and corruption detection are all preserved — see
   §6.
3. **Explicit selection only (during development).** `craft nano`/`craft macro`
   keep their exact current behaviour. New `craft nano-stream` / `craft macro-stream`
   commands (and a `--stream` flag) opt in. No auto-replacement.
4. **Atomicity.** The final archive is written to a sibling temp file and renamed
   into place only after a read-back confirmation — mirroring the existing
   `safeWriteFile` guarantees. The intermediate compressed-chunk file is always
   cleaned up, even on interruption.

## 4. Compression strategy (streaming-native)

The streaming path compresses each chunk with a **self-contained, independently
decodable** codec so that chunks are truly independent (a corrupt chunk cannot
poison later chunks, and chunks can be decoded in parallel).

| Strategy key | Codec | Notes |
|---|---|---|
| `zstd` *(default)* | Zstd, independent per-chunk frames | Fastest; scales to GB files. Level configurable (`--level`, default 19, max 22). |
| `brotli` | Brotli Q11 (independent per-chunk streams) | Highest ratio for the streaming path; slower. `--quality` 0–11. |

> `compress7` (the 7-fold engine, strategies 0–12) is **not** used on the
> streaming path because its *adaptive-selection* step is whole-file by design.
> Strategy `12` (craft-codec order-1) is likewise O(256)/symbol and remains
> confined to `compress7` on inputs ≤ 4 MB.

`compressionMode` in a v4 package is `"stream"` and `compressionStrategyName`
records the concrete streaming strategy (e.g. `"Zstd L19 chunked streaming"`).

## 5. Constant-memory data flow

### Encoding (`nanoStream`) — single read, temp chunk file, atomic assemble

```
file stream ─► [SHA-256] ─► [split to chunkSize] ─► [compress chunk] ─► [AES-256-GCM per chunk]
                     │                                                         │
                     ▼                                                         ▼
            running digest                                                chunk records
                                                                        ─► temp chunk file   (disk, constant RAM)
                                                                                          │
                  ──► header + encrypted metadata ──► final temp file ──► stream-copy temp  ──► atomic rename
```

- The input is read via `fs.createReadStream` with `highWaterMark = chunkSize`
  and re-chunked into fixed `chunkSize` boundaries (last chunk may be shorter).
- At any instant the encoder holds **at most one** logical chunk: the raw chunk
  (≤ `chunkSize`), its compressed form (≤ `chunkSize`), and its ciphertext
  (≤ `chunkSize`) — i.e. roughly `3 × chunkSize` of heap, **independent of file
  size**. The compressed/encrypted chunk records are flushed straight to the
  temp chunk file; they are never all held in RAM.
- A single PBKDF2 (600 000 iter) derives the **archive data key** from one
  random `DATA_SALT` (16 B); that key is reused for every chunk with a
  freshly-random 96-bit per-chunk IV + 128-bit GCM tag.
- After all chunks are written, the metadata JSON (which needs
  `compressedSize`/`originalSize`/`originalChecksum` only known at the end) is
  encrypted and the **header is assembled first**, then the temp chunk file is
  stream-copied behind it, and the result is atomically renamed onto the
  destination (read-back verified). The temp chunk file is deleted.

### Decoding (`macroStream`) — single pass, streaming

```
file stream ─► header ─► decrypt metadata ─► [ loop: read chunk record ]
                                                       │
                                                       ▼
                                          [AES-GCM decrypt] ─► [decompress] ─► [SHA-256] ─► output stream / file
```

- Only one chunk (its ciphertext + plaintext) is in memory at a time.
- Per-chunk AES-GCM tag and per-chunk decompression are checked independently;
  a failure on any chunk throws immediately (no partial/corrupt output is
  silently emitted — see §7).
- After the final chunk, the running SHA-256 is compared to
  `metadata.originalChecksum` **and** the restored byte count is compared to
  `metadata.originalSize` (catches truncation).

### v1–v3 fallback

`macroStream` accepts any CRAFT archive: for version 1/2/3 it delegates to the
unchanged `macro()` (which loads the whole package — as it always did). Only
v4 archives take the streaming path. This keeps the gold-standard reader
byte-identical while making the streaming reader universal.

## 6. Security model (unchanged guarantees)

| Guarantee | v1–v3 | v4 (streaming) |
|---|---|---|
| Encryption | AES-256-GCM | **AES-256-GCM** (per-chunk 96-bit IV + 128-bit tag; shared key from one PBKDF2-600k) |
| Key derivation | PBKDF2-SHA256, 600 000 iter, 16 B random salt | Same (one data salt + one metadata salt, 600 000 iter) |
| Integrity | SHA-256 of original, verified on restore | Same, accumulated incrementally over the stream |
| Authentication / tamper detection | AES-GCM auth tag(s) + magic/version/metadata guards | Same, *strengthened*: per-chunk tag + final SHA-256 + byte count |
| Metadata privacy | Encrypted (AES-GCM) unless `encryptMetadata:false` | Encrypted (always, bit-31 flag set) |
| Corruption detection | magic, version, ML bounds, AES-GCM, JSON, SHA-256 | same + per-chunk AES-GCM + per-chunk decompress + final SHA-256 + count |

**Sharing a GCM key across chunks is safe:** AES-256-GCM's security reduces to
nonce uniqueness; each chunk uses a freshly random 96-bit IV, so the 2^96 nonce
space makes IV reuse astronomically unlikely. This is the standard "many
messages, one key" AEAD deployment — it is *not* a weakening.

## 7. Failure recovery & atomicity

- The encoded archive is built in a **sibling temp file** (`<dest>.<pid>.crafttmp`)
  and only `renameSync`'d into place **after** a read-back byte comparison
  (identical to the existing `safeWriteFile`). A crash never leaves a truncated
  file at the destination.
- The intermediate **chunk temp file** is written to the OS temp dir and
  `unlinkSync`'d in a `finally`/cleanup block — it is removed whether the run
  succeeds, fails, or is killed (SIGKILL/SIGTERM) mid-stream. No `.craft` or
  `.crafttmp` artifacts are left behind.
- On decode, if any per-chunk tag/decompress/checksum step fails, the error is
  thrown and the (possibly partial) output file is **not** considered valid —
  callers using an explicit output path get a deterministic failure, not a
  half-written file. Atomic decode-to-file uses the same temp+rename pattern.

## 8. Public API

```ts
// src/lib/craft/nanoStream.ts
export async function nanoStream(
  input: string | NodeJS.ReadableStream,       // file path or readable stream
  originalName: string,
  originalMime: string,
  passphrase: string,
  opts?: NanoStreamOptions,                    // chunkSize, strategy, level/quality, verify, output
): Promise<NanoStreamResult>

// src/lib/craft/macroStream.ts
export async function macroStream(
  input: string | Buffer | NodeJS.ReadableStream,  // file path, in-memory buffer, or readable
  passphrase: string,
  opts?: MacroStreamOptions,                       // output path/Writable, chunkSize (decode), strategy
): Promise<MacroStreamResult>

export function peekStreamMetadata(craftBuffer: Buffer): StreamMetadata   // sync peek for v4
```

`NanoStreamResult` / `MacroStreamResult` mirror `NanoResult` / `MacroResult`
where it matters (`metadata`, `compressionRatio`, `spaceSaved`,
`integrityVerified`, `buffer?`) plus streaming-specific counters
(`chunksProcessed`, `bytesProcessed`, `bytesRestored`, `chunksRead`,
`archiveBytes`, `peakMemoryHint?`).

## 9. Validation contract

Against the gold-standard `nano()`/`macro()` on identical inputs:

- ✅ restored bytes are **bit-identical** to the original (and identical between
  `macro(nano(x))` and `macroStream(nanoStream(x))`);
- ✅ SHA-256 of restored equals `metadata.originalChecksum` and equals `nano`'s;
- ✅ both detect a 1-byte flip (incorrect passphrase ⇒ AES-GCM tag mismatch;
  tampering ⇒ per-chunk tag + final SHA-256 mismatch);
- ✅ CLI behaviour matches (`--force`, `-o`, passphrase rules, exit codes,
  fixity sidecar on `nano-stream`).

## 10. Performance / memory targets

- **Peak memory** stays ≈ `3 × chunkSize + ε` regardless of file size. Default
  `chunkSize = 1 MB`. (Compare `nano()`'s ≈ `3 × input size`.)
- Scales to 1 GB / 5 GB / 10 GB without proportional RAM growth; throughput
  bounded by CPU (Zstd) / I/O, not by archive size.
- Compression ratio is streaming-native: Zstd chunked vs. 7-fold Brotli/Q11/Zstd
  is slightly lower (no cross-chunk dictionary), documented in the perf report.
