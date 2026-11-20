# Craft Engine (craft-engine)

A high-integrity, adaptive encryption and compression suite for Node.js, designed for maximum-density archival with guaranteed fidelity. Craft Engine is delivered as a headless library, CLI, and framework-neutral HTTP adapter; this repository does not ship a standalone web UI or authentication service.

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

## Install from npm

```bash
npm install craft-engine
```

This installs the Craft Engine library and the `craft` CLI executable. Import the HTTP adapter from `craft-engine/lib/craft/http-adapter` when mounting framework-neutral create/restore routes.

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

### CLI: the four-command design

Compression and encryption are separate operations. `nano`/`macro` only compress and inflate a standalone `.nano` package; `craft`/`uncraft` create and restore encrypted production `.craft` archives.

| Command | Purpose | Default output |
| --- | --- | --- |
| `nano <file>` | Compress a regular file; does **not** encrypt it | `<file>.nano` |
| `macro <file.nano>` | Inflate a `.nano` package; does **not** decrypt it | Original filename stored in the package |
| `craft <file> -p <passphrase>` | Compress and encrypt with the production Craft engine | `<file>.craft` plus `<file>.craft.fixity.json` |
| `uncraft <file.craft> -p <passphrase>` | Decrypt and restore a production Craft archive | Original filename recorded in the archive |

Run the commands from a source checkout after installing dependencies and building the library:

```bash
npm install
npm run build:lib

# Compression only: creates my-data.tar.nano; this file is not encrypted.
node bin/craft.js nano my-data.tar

# Inflate it back to the original filename.
node bin/craft.js macro my-data.tar.nano

# Encrypt with the production format. Use a strong passphrase (at least 12 characters).
node bin/craft.js craft my-data.tar -p "your-secure-passphrase"

# Decrypt and restore the original file.
node bin/craft.js uncraft my-data.tar.craft -p "your-secure-passphrase"

# Check fixity records for a file or directory.
node bin/craft.js verify my-vault/
```

Both compression commands accept `-o <path>` / `--output <path>` to choose an output and `-f` / `--force` to permit overwriting. For example, `node bin/craft.js nano report.csv -o backups/report.nano` and `node bin/craft.js macro backups/report.nano -o restored-report.csv`. The same `-o` and `-f` options are supported by the production archive commands; pass them after the passphrase as needed. Without force, an existing output is left untouched and the command fails rather than overwriting it.

The standalone `.nano` container is a compression format, not an encrypted archive: do not use it to protect sensitive files. `craft`/`uncraft` use the repository's existing production archive implementation, preserving its format, adaptive compression, AES-GCM authenticated encryption, fixity sidecars, and other production security features. These production `.craft` archives are distinct from `.nano` files and remain compatible with the pre-update engine. The four CLI commands currently accept regular files; the CLI does not pack folders into the standalone `.nano` format.

### Existing command compatibility

The original encrypted commands remain available without changing their behavior:

```bash
node bin/craft.js legacy-nano my-data.tar -p "your-secure-passphrase"
node bin/craft.js legacy-macro my-data.tar.craft -p "your-secure-passphrase"
```

These are aliases for the former encrypted `nano` and `macro` commands. They use the same production archive format as `craft`/`uncraft`; they are provided so existing scripts that need the old command names can keep working after the primary command meanings changed. Existing production `.craft` archives remain handled by `craft`/`uncraft`, `legacy-macro`, and the library APIs. All auxiliary production commands (`doctor`, `verify`, `watch`, passkeys, streaming, and others) remain available.

The supplied reference PDF is retained at [`docs/updates/craft-engine-update-reference.pdf`](docs/updates/craft-engine-update-reference.pdf). Its illustrative `CRAFT01` container is not used for production archives, because that format is explicitly documented as incompatible with the production repository's archive format.

### Artifact icons

The supplied artwork is preserved byte-for-byte in [`assets/craft-icons/source/`](assets/craft-icons/source/). Optimized WebP assets are included under `public/craft-icons/` for downstream apps to serve or copy into their own public assets. The mapping and filename resolver live in [`src/lib/craft/artifact-icons.ts`](src/lib/craft/artifact-icons.ts), so adapters and host apps can make the same association without depending on a Craft Engine UI.

| Supplied image | Meaning | Current artifact |
| --- | --- | --- |
| `Compressed_Only.png` | Compression, no encryption | Standalone `.nano` output |
| `Encrypted_Only.png` | Encryption, no compression | Demo-only `.encdemo` fixture; no encryption-only production output mode |
| `Compressed & Encrypted.png` | Compression followed by encryption | Production `.craft` output |

The production archive engine compresses its payload before encrypting it. The `.encdemo` example is a separate test envelope used only to verify the encryption-only icon; `uncraft` does not read it. Do not use that icon to label `.craft` archives. See [`examples/icon-verification/`](examples/icon-verification/) for reproducible samples and the demo-only passphrase.

### Library

```typescript
import { nano, macro } from 'craft-engine/lib/craft';

// Crafting
const { buffer } = await nano(originalData, 'filename.txt', 'text/plain', 'passphrase');

// Restoring
const restored = await macro(buffer, 'passphrase');
```

### Headless application adapter

The `./lib/craft` export also provides standard Fetch API `Request`/`Response` handlers for host applications that want HTTP endpoints without embedding a Craft Engine UI or depending on Next.js:

```typescript
import { createCraftHttpAdapter } from 'craft-engine/lib/craft';

const craft = createCraftHttpAdapter({
  maxFileSizeBytes: 100 * 1024 * 1024,
  corsOrigin: 'https://your-app.example', // omit to leave CORS disabled
});

// Mount craft.create and craft.restore as POST handlers in your server/framework.
// Mount craft.options for OPTIONS preflight requests.
```

The adapter expects multipart fields named `file` and `passphrase`; it returns `.craft` bytes with icon/metadata headers or restored file bytes. Host applications remain responsible for authentication, rate limiting, request-body limits, and allowed origins. The same operations can be invoked directly with `nano()` and `macro()` when an HTTP boundary is not needed. A focused import is also available as `craft-engine/lib/craft/http-adapter`. See the [complete Express integration example](examples/http-adapter/express/README.md), with a bridge server, size limits, auth hooks, CORS notes, and curl requests.

## Development

- `npm run test`: Run the Vitest suite.
- `npm run build`: Build the library, adapter, and CLI package.
- `npm run lint`: Run framework-independent TypeScript ESLint checks.

## License

MIT - See [LICENSE](./LICENSE) for details.
