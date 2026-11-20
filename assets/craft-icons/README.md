# Craft artifact icons

The exact supplied source PNGs are preserved in `source/` with their original filenames. Optimized WebP copies in `public/craft-icons/` are used by the web UI. The WebP files are resized to 384 × 384 for efficient rendering; the original PNGs are unchanged.

| Source asset | Web asset | Intended state | Current output |
| --- | --- | --- | --- |
| `Compressed_Only.png` | `/craft-icons/compressed-only.webp` | Compression without encryption | Standalone `.nano` packages |
| `Encrypted_Only.png` | `/craft-icons/encrypted-only.webp` | Encryption without compression | Demo-only `.encdemo` fixture; no encryption-only production package is emitted by the engine |
| `Compressed & Encrypted.png` | `/craft-icons/compressed-encrypted.webp` | Compression and encryption together | Production `.craft` archives |

The icon mapping is centralized in `src/lib/craft/artifact-icons.ts`. Do not display the encryption-only icon for a `.craft` artifact: the production engine compresses its payload before encrypting it. The `.encdemo` envelope exists only to verify the encryption-only icon and is not readable by `uncraft`. The web dashboard currently emits the combined archive type and displays the matching combined icon with its successful download result.
