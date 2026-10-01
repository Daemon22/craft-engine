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

### CLI

```bash
# Verify the environment
node bin/craft.js doctor

# Compress a file (Nano)
node bin/craft.js nano my-data.tar -p "your-secure-passphrase"

# Restore a file (Macro)
node bin/craft.js macro my-data.tar.craft -p "your-secure-passphrase"

# Verify fixity/integrity
node bin/craft.js verify my-vault/
```

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
