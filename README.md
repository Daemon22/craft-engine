# Craft Engine (@manya/craft-engine)

A high-integrity, adaptive encryption and compression suite for Node.js, designed for maximum-density archival with guaranteed fidelity.

## Key Features

- **12-Strategy Adaptive Compression**: Automatically selects the best algorithm (Brotli, Zstd, or the custom `craft-codec` range coder) to achieve the smallest possible file size.
- **Hardened Security**: AES-256-GCM authenticated encryption with 600,000 PBKDF2 iterations.
- **Self-Verification**: The engine automatically decrypts and decompresses the archive in-memory immediately after creation to ensure 100% restore fidelity.
- **Bitrot Detection**: Generates fixity sidecar files (.fixity.json) containing SHA-256 hashes to monitor long-term data integrity.
- **Streaming Support**: Constant-memory v4 streaming for processing multi-gigabyte files without high RAM overhead.
- **Environment Doctor**: Built-in self-test (`craft doctor`) to verify environment compatibility and strategy support.

## Project Structure

- `src/lib/craft/`: The primary, hardened sync implementation (recommended for production).
- `src/lib/`: Legacy async implementation (historical usage).
- `craft-codec/`: A standalone Carryless Range Coder used as a specialized compression strategy.
- `bin/`: CLI entry point (`craft` command).
- `docs/`: Technical specifications for streaming and chunk formats.

## Installation & Setup

```bash
# Clone the repository
git clone https://github.com/Daemon22/craft-engine.git
cd craft-engine

# Install dependencies
npm install

# Build the library
npm run build:lib
```

## Usage

### CLI: compression and encryption are separate operations

The four primary commands give compression and encryption distinct roles:

```bash
# Compression only: creates my-data.tar.nano (not encrypted)
node bin/craft.js nano my-data.tar

# Reverse compression only: restores the original file
node bin/craft.js macro my-data.tar.nano

# Encrypt using the production Craft archive format (with adaptive compression)
node bin/craft.js craft my-data.tar -p "your-secure-passphrase"

# Decrypt and restore an existing production Craft archive
node bin/craft.js uncraft my-data.tar.craft -p "your-secure-passphrase"

# Verify fixity/integrity
node bin/craft.js verify my-vault/
```

`nano`/`macro` handle standalone `.nano` compression packages only; they do not encrypt or decrypt. `craft`/`uncraft` route through the existing production `nano()`/`macro()` engine, preserving its archive format, adaptive compression, authenticated encryption, fixity records, and supported security features. Use `-o <path>` to select an output and `-f` to allow overwriting.

### Existing command compatibility

The original encrypted commands remain available without changing their behavior:

```bash
node bin/craft.js legacy-nano my-data.tar -p "your-secure-passphrase"
node bin/craft.js legacy-macro my-data.tar.craft -p "your-secure-passphrase"
```

These are aliases for the former encrypted `nano` and `macro` commands. Existing production `.craft` archives remain handled by `craft`/`uncraft` and `legacy-macro`; the standalone `.nano` container is a separate compression-only format and is not a replacement for, or decryptor of, production `.craft` archives. All auxiliary production commands (`doctor`, `verify`, `watch`, passkeys, streaming, and others) remain available.

The supplied reference PDF is retained at [`docs/updates/craft-engine-update-reference.pdf`](docs/updates/craft-engine-update-reference.pdf). Its illustrative `CRAFT01` container is not used for production archives, because that format is explicitly documented as incompatible with the production repository's archive format.

### Library

```typescript
import { nano, macro } from '@manya/craft-engine/lib/craft';

// Crafting
const { buffer } = await nano(originalData, 'filename.txt', 'text/plain', 'passphrase');

// Restoring
const restored = await macro(buffer, 'passphrase');
```

## Development

- `npm run test`: Run the Vitest suite.
- `npm run build`: Build for production.
- `npm run lint`: Run ESLint.

## License

MIT - See [LICENSE](./LICENSE) for details.
