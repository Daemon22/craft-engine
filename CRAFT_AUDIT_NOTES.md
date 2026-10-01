# CRAFT Engine Audit Notes & Hardening History

This document tracks the evolution of security measures and architectural decisions for the `@manya/craft-engine`.

## The Hardening Pillars

The `src/lib/craft` implementation was built to address specific reliability gaps found in the legacy async implementation:

1. **Pillar A: Self-Verification**
   - **Problem**: Rare compression or encryption bugs could lead to unreadable archives that are only discovered months later during a restore attempt.
   - **Solution**: `nano()` performs an in-memory `macro()` round-trip before returning. If the decrypted/decompressed result doesn't match the original, it throws immediately.
   - **Status**: Enabled by default in `nano.ts`.

2. **Pillar B: Atomic, Non-Destructive Writes**
   - **Problem**: A crash or disk-full error mid-write could corrupt an existing backup or leave a truncated file.
   - **Solution**: The CLI uses `safeWriteFile` (write to `.crafttmp` -> verify read-back -> atomic `renameSync`).
   - **Status**: Enforced in `cli/index.ts`.

3. **Pillar C: Environment Doctor**
   - **Problem**: Missing `zstd` support in older Node versions or mangled dependency resolution.
   - **Solution**: `craft doctor` exercises every strategy family with real fixtures.
   - **Status**: Implemented in `self-test.ts`.

4. **Pillar D: Golden Fixture**
   - **Problem**: Code changes silently breaking compatibility with old archives.
   - **Solution**: `tests/craft-golden-fixture.test.ts` ensures v1-v3 packages always decode to the same bytes.
   - **Status**: Verified in Vitest suite.

5. **Pillar E: Fixity Checking**
   - **Problem**: Bitrot (silent disk corruption) on files sitting untouched for years.
   - **Solution**: `.fixity.json` sidecars containing SHA-256 and size metadata.
   - **Status**: Supported via `craft verify`.

6. **Pillar F: Scheduled Verification**
   - **Problem**: Manual verification is rarely done.
   - **Solution**: `craft watch` loops verification on a schedule.
   - **Status**: Supported via CLI and `deploy/` templates.

## Implementation Split & Consolidation Plan

Currently, the project contains two parallel exports:
- `.` (Legacy): Async, `CRAFT_VERSION=2`, supports multi-file archives.
- `./lib/craft` (Hardened): Sync, `CRAFT_VERSION=3`, supports v4 streaming.

**Decision**: The Hardened implementation is the "Gold Standard" for integrity. Future work will merge these into a single unified API that provides the async benefits of the legacy path with the safety guarantees of the hardened path.

## Version Lineage
- **v1**: Single blob, Brotli, AES-GCM, plaintext metadata.
- **v2**: Adaptive 7-fold compression.
- **v3**: Metadata encryption support (Sync path) / Multi-file archives (Legacy path).
- **v4**: Constant-memory chunked streaming.
