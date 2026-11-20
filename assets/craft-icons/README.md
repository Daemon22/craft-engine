# Craft artifact icons

The exact supplied source PNGs are preserved in `source/` with their original filenames. Optimized WebP copies in `public/craft-icons/` are package assets for downstream applications to serve or copy into their own public directories. The WebP files are resized to 384 × 384 for efficient rendering; the original PNGs are unchanged.

| Source asset | Consumer asset path | Intended state | Current output |
| --- | --- | --- | --- |
| `Compressed_Only.png` | `/craft-icons/compressed-only.webp` | Compression without encryption | Standalone `.nano` packages |
| `Encrypted_Only.png` | `/craft-icons/encrypted-only.webp` | Encryption without compression | Demo-only `.encdemo` fixture; no encryption-only production package is emitted by the engine |
| `Compressed & Encrypted.png` | `/craft-icons/compressed-encrypted.webp` | Compression and encryption together | Production `.craft` archives |

The icon mapping and extension resolver are centralized in `src/lib/craft/artifact-icons.ts` and exported through `craft-engine/lib/craft`. Do not display the encryption-only icon for a `.craft` artifact: production Craft archives compress their payload before encrypting it. The `.encdemo` envelope exists only to verify the encryption-only icon and is not readable by `uncraft`. No web UI is included in this repository.
