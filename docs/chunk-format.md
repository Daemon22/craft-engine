# CRAFT Chunk Format (v4 — Chunked Streaming)

> Companion to [`streaming-architecture.md`](./streaming-architecture.md).
> This is the **authoritative on-disk layout** for the v4 streaming archive
> produced by `nanoStream()` and consumed by `macroStream()`. Legacy v1/v2/v3
> archives are unchanged and still read by `macro()` / `peekMetadata()`.

## 1. Magic & version

| Field | Offset | Size | Value |
|---|---|---|---|
| `MAGIC` | 0 | 6 B | `0x43 52 41 46 54 31` = `"CRAFT1"` (same bytes as v1–v3) |
| `VERSION` | 6 | 1 B | `0x04` |

Reusing `CRAFT1` and adding `VERSION = 4` means the magic-based sniff is
unchanged; only the version byte increments. `macro()`/`peekMetadata()` reject
unknown versions (`> 3`) with a clear error — v4 packages therefore opt into
the new reader (`macroStream` / `peekStreamMetadata`); they are never silently
mis-parsed as v1–v3.

## 2. Header (variable)

Immediately after `VERSION`:

| Field | Size | Semantics (BE = big-endian) |
|---|---|---|
| `ML` | 4 B `uint32` | Bit 31 (`METADATA_ENCRYPTED_FLAG = 0x80000000`) set ⇒ encrypted metadata (always set for v4). Low 31 bits ⇒ `metadataSectionLength`. |
| Metadata section | `metadataSectionLength` B | Only present/structured when encrypted (v4): `META_SALT(16) + META_IV(12) + META_AUTH_TAG(16) + ENCRYPTED_META(remaining)`. `ENCRYPTED_META = AES-256-GCM(JSON)`. See §3. |
| `DATA_SALT` | 16 B | PBKDF2 salt for the **data key** (one per archive). |
| `CHUNK_COUNT` | 4 B `uint32` | Number of chunk records that follow. |
| `CHUNK_SIZE` | 4 B `uint32` | Nominal chunk size in bytes used at encode time (default 1 048 576 = 1 MB). Configurable. |
| `ORIGINAL_SIZE` | 8 B (`uint32` high + `uint32` low) | Total size of the original (pre-compression) plaintext. Supports files > 4 GB. |

After the header, exactly `CHUNK_COUNT` chunk records are laid out back-to-back
(no length prefix on the whole chunk region — `CHUNK_COUNT` bounds it).

## 3. Metadata JSON (encrypted, v4)

Encrypted with AES-256-GCM using a **metadata key** derived via PBKDF2-SHA256
(600 000 iter) from `META_SALT` + passphrase (same primitive as v1–v3
`encryptMetadata`). Fields:

```jsonc
{
  "version": 4,
  "originalName": "video.mp4",           // original filename
  "originalMime": "video/mp4",            // original MIME
  "originalSize": 1073741824,            // total plaintext bytes (must equal header ORIGINAL_SIZE)
  "compressedSize": 220200960,           // sum of per-chunk compressed (pre-encryption) payload bytes
  "compressionMode": "stream",           // v4 = "stream" (v1–v3 = "brotli" | "7fold")
  "compressionStrategyName": "Zstd L19 chunked streaming", // concrete streaming strategy
  "encryptionAlgo": "aes-256-gcm",
  "originalChecksum": "<sha256 hex of whole plaintext>",
  "chunkSize": 1048576,
  "chunkCount": 1024,
  "metadataEncrypted": true,
  "createdAt": "2026-08-05T17:19:07.761Z"
}
```

For **`peek`** without a passphrase, the CLI surfaces the public fields from §2
(`ORIGINAL_SIZE`, `CHUNK_COUNT`, `CHUNK_SIZE`, `VERSION`) and redacts the
encrypted metadata fields (identical to how `peek` behaves on encrypted v3
packages — see `peekMetadata`).

## 4. Chunk record layout (repeated `CHUNK_COUNT` times)

Each chunk is an **independently authenticatable, independently decompressible**
unit. The data key (from `DATA_SALT`) is shared across all chunks; the nonce
(`CHUNK_IV`) is fresh and random per chunk.

| Field | Size | Semantics |
|---|---|---|
| `COMP_LEN` | 4 B `uint32` | Length in bytes of `CHUNK_CIPHERTEXT` (equals the compressed length, since AES-GCM is a stream cipher; the auth tag is separate). |
| `CHUNK_IV` | 12 B | Random 96-bit nonce for this chunk (AES-256-GCM). |
| `CHUNK_AUTH_TAG` | 16 B | 128-bit GCM authentication tag for this chunk. |
| `CHUNK_CIPHERTEXT` | `COMP_LEN` B | `AES-256-GCM-encrypt(chunkCompressedData)` using the data key + `CHUNK_IV`. |

Where `chunkCompressedData` is the output of the streaming compressor applied to
**exactly** the plaintext bytes of this chunk (a full independent codec frame:
a Zstd frame, or a complete Brotli stream, for that chunk only).

### Chunk numbering / ordering

Chunks are numbered implicitly by position (`0 .. CHUNK_COUNT-1`) and are always
stored and read in ascending order. Chunk `i` covers original bytes
`[i*CHUNK_SIZE .. min((i+1)*CHUNK_SIZE, ORIGINAL_SIZE))`; the final chunk is
the remainder and is `ORIGINAL_SIZE - (CHUNK_COUNT-1)*CHUNK_SIZE` bytes. A reader
must never emit more plaintext than `ORIGINAL_SIZE` total (guards truncation and
over-long final chunks).

## 5. Worked sizes

Per-chunk record overhead = `4 + 12 + 16 = 32 B` (plus the ciphertext itself).
Archive total ≈ `headerOverhead + Σ(compLen_i + 32)`.

Header overhead (v4, encrypted metadata) =

`11` (MAGIC+VER+ML) `+ 44` (META_SALT+IV+TAG) `+ ENC_META` `+ 16+4+4+8`
(dataSalt+chunkCount+chunkSize+origSize)

= `83 + ENC_META` bytes, where `ENC_META` ≈ `len(JSON_metadata) + 16`.

## 6. Backward compatibility

- `macro()` (gold standard) reads v1/v2/v3 **unchanged**. It does **not** know
  v4 and will throw `Unsupported CRAFT version: 4` — v4 archives are opened with
  `macroStream()` (or `craft macro-stream` / `craft macro --stream`).
- `macroStream()` is universal: it peeks the version byte and delegates v1/v2/v3
  to the unchanged `macro()`, taking the streaming path only for v4.
- `nano()` remains the v1–v3 in-memory writer; `nanoStream()` is the v4
  streaming writer. Existing archives never change.
- `peekStreamMetadata()` handles v4; `peekMetadata()` handles v1–v3. The CLI
  `craft peek` auto-dispatches by version.

## 7. Corruption / tamper matrix

| Corruption site | Detected by | Throws |
|---|---|---|
| Bad magic | header | `magic bytes mismatch` |
| Wrong version (not 1–4) | header | `Unsupported CRAFT version` |
| Tampered metadata | `META_AUTH_TAG` | `Metadata decryption failed — the passphrase is incorrect.` |
| Wrong passphrase | `CHUNK_AUTH_TAG` (per chunk) | `Decryption failed — incorrect passphrase.` |
| Flipped ciphertext byte | `CHUNK_AUTH_TAG` | `Integrity failure ...` |
| Truncated final chunk | per-chunk decrypt + byte-count check | `truncated` / `byte-count mismatch` |
| Whole-archive SHA drift | `originalChecksum` vs running SHA-256 | `INTEGRITY FAILURE: SHA-256 checksum mismatch` |
| Over-long final chunk | byte-count vs `ORIGINAL_SIZE` | byte-count mismatch error |

A failing chunk aborts the whole restore (no partial, silently-truncated
output), preserving the atomicity contract.
