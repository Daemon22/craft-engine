# craft/ — the `./lib/craft` subpath (@manya/craft-engine/lib/craft)

This is a separate, sync-API implementation living alongside the
package's primary export (`src/lib/index.ts` — see the top-level
`README.md`). It has its own compression strategy set, its own
metadata-encryption option, and — as of this session — its own set of
hardening measures the primary export doesn't have yet. **If you're
deciding which to use: this one has more compression strategies and
more safety guarantees; the primary export has more historical usage.**
Consolidating them is an open decision — see `CRAFT_AUDIT_NOTES.md`.

Everything below is real, tested, and wired together — this doc is the
map of how the pieces connect, not a wishlist.

## The full circuit

```
                     ┌─────────────────────────────────────────┐
                     │              nano(data, ...)             │
                     │                                           │
  raw file  ────────►│  12-strategy adaptive compression         │
                     │  (Brotli / Zstd / Craft-Codec, picks       │
                     │   smallest — see compress7.ts)             │
                     │              │                             │
                     │              ▼                             │
                     │  AES-256-GCM encrypt (+ separately          │
                     │   encrypted or plaintext metadata)          │
                     │              │                             │
                     │              ▼                             │
                     │  SELF-VERIFY: decrypt+decompress the       │
                     │  package just built, in memory, compare    │
                     │  to the original — throws if it doesn't    │
                     │  match (on by default, see nano.ts)        │
                     └──────────────┬────────────────────────────┘
                                    │ .craft package (Buffer)
                     ┌──────────────▼────────────────────────────┐
                     │         CLI: `craft nano <file>`            │
                     │                                             │
                     │  safeWriteFile(): refuses to overwrite      │
                     │  an existing output without --force,        │
                     │  writes to a temp file + atomic rename,     │
                     │  reads back to confirm the disk write       │
                     │  matches what was intended                  │
                     │              │                              │
                     │              ▼                              │
                     │  recordFixitySidecar(): SHA-256 + size of   │
                     │  the package, written as <file>.fixity.json │
                     │  (same safeWriteFile guarantees)             │
                     └──────────────┬────────────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
     `craft verify <path>`   `craft watch <dir>`    `craft doctor`
     one-shot fixity scan    loops verify on a       round-trips real
     (or --deep: full        schedule, forever,      fixtures through
     decrypt check),         logs every cycle,        every strategy
     exits non-zero on       flags failures loudly    family, checks
     any failure — safe      but keeps running        Node/Zstd support
     for scripts/cron        (see deploy/ for         — run this once
                              systemd/cron setup)      per environment
```

Restoring a file (`macro()` / `craft macro`) runs the same
decrypt→decompress→checksum-verify chain nano's self-check already
exercised, plus the CLI's same `safeWriteFile` protection on the way
back out to disk.

## Quick start

```bash
# One file
craft nano secret.txt -p "your passphrase"        # → secret.txt.craft + secret.txt.craft.fixity.json
craft macro secret.txt.craft -p "your passphrase"  # → secret.txt (restored, byte-identical)

# Check the whole environment works before trusting it with anything real
craft doctor

# Check a vault directory for bitrot — no passphrase needed for this
craft verify /path/to/vault

# Same, but continuously, forever, logging every cycle
craft watch /path/to/vault --interval 1h --log /var/log/craft-verify.log
```

To make `craft watch` (or scheduled `craft verify`) survive reboots and
actually run unattended, see `deploy/systemd/` (recommended on Linux) or
`deploy/cron/craft-verify.cron` (everywhere else). Both are ready-to-edit
templates, not just documentation — copy, fill in the two placeholders,
install.

## The hardening pillars (see CRAFT_AUDIT_NOTES.md for the full history)

| Pillar | What it catches | Where |
|---|---|---|
| A. Self-verification | A broken compress/decrypt pairing, at the moment of creation | `nano.ts` (`NanoOptions.verify`, default on) |
| B. Atomic, non-destructive writes | Crashes mid-write, accidental overwrites | `cli/index.ts` (`safeWriteFile`) |
| C. Environment doctor | Wrong Node version, missing Zstd, broken dependency resolution | `self-test.ts`, `craft doctor` |
| D. Golden fixture | A future code change silently breaking old files | `tests/craft-golden-fixture.test.ts` |
| E. Fixity checking | Bitrot / corruption on files untouched on disk | `fixity.ts`, `craft verify` |
| F. Scheduled verification | The same, but automatically instead of manually | `craft watch`, `deploy/` |

## Compression strategies (12, adaptive — see compress7.ts)

Every `nano()` call tries every applicable strategy and keeps whichever
produces the smallest output — nothing here is a fixed choice:

- **0–9**: Brotli Q11, optionally pre-processed with delta / move-to-front
  / run-length / byte-pair encoding, alone or combined.
- **10–11**: Zstd (level 22, long window) — a different match-finder and
  entropy coder than Brotli; wins on some inputs Brotli doesn't.
- **12**: `@manya/craft-codec` — an original, from-scratch adaptive
  order-1 context-modeling range coder (not a Brotli/Zstd wrapper — a
  genuinely different compression theory). Wins on data with strong
  local byte statistics and few long verbatim repeats; gated to inputs
  ≤4MB. See the sibling `craft-codec` package for its own docs and tests.

## What this doesn't do (yet)

- The primary export (`src/lib/index.ts`) doesn't have pillars A/C/E/F —
  only this subpath does. See `CRAFT_AUDIT_NOTES.md` for the
  consolidation question.
- `craft watch` schedules itself in-process; it doesn't install itself as
  a service — that's what `deploy/` is for, and it's a manual step.
- Fixity sidecars are plaintext JSON next to an encrypted package — they
  reveal package size and creation time (not contents). Worth knowing if
  that metadata itself needs to be hidden.
- No automated corruption *repair* — everything here detects and reports;
  recovering from a real failure still means restoring from a backup.
