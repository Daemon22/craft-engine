# HAEL Codex Asset Assignment — Craft Engine

Canonical source matrix: https://github.com/Daemon22/haelfoundation/blob/main/canon/COMPLETE-CODEX-ASSET-AND-VOICE-MATRIX.md

## Repository responsibility
Craft Engine is the archive/packaging and authenticated-encryption layer. Its role is to preserve and package exact source artifacts with integrity metadata; it is not the canonical home of intelligence portraits or voice identities.

## Canonical artifact handling
- Preserve original bytes and filenames.
- Include source SHA-256, identity, source repository/path, and consent/provenance metadata when packaging audio.
- Never crop/re-encode canonical images as part of archival ingestion.
- Missing assets must be reported; no synthetic replacements.

## Voice
The Codex states a shared TTS model. No canonical audio files are identified in the assignment record. Do not package a nonexistent recording or infer consent.