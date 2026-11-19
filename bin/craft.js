#!/usr/bin/env node
'use strict';

/**
 * Craft CLI compatibility router.
 *
 * nano/macro implement standalone compression-only .nano packages.
 * craft/uncraft route to the production encrypted archive implementation,
 * retaining its existing package format and security controls.
 * legacy-nano/legacy-macro preserve the former CLI command names exactly.
 * All other production commands continue to route to the original CLI.
 */
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const MAGIC = Buffer.from('NANO02');
const HEADER_FIXED = MAGIC.length + 4 + 8;

function fail(message) {
  console.error(`craft: ${message}`);
  process.exit(1);
}

function parseOptions(argv) {
  const positional = [];
  let output;
  let force = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-o' || arg === '--output') {
      output = argv[++i];
      if (!output) fail(`${arg} requires a path`);
    } else if (arg === '-f' || arg === '--force') {
      force = true;
    } else if (arg === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    } else if (arg.startsWith('-')) {
      fail(`unknown argument: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  return { positional, output, force };
}

function safeWrite(filePath, data, force) {
  if (fs.existsSync(filePath) && !force) fail(`${filePath} exists — pass -f to overwrite`);
  const absolutePath = path.resolve(filePath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  const tempPath = path.join(path.dirname(absolutePath), `.${path.basename(absolutePath)}.crafttmp-${process.pid}`);
  try {
    fs.writeFileSync(tempPath, data, { flag: 'wx' });
    if (force) {
      fs.renameSync(tempPath, absolutePath);
    } else {
      // link() publishes atomically and fails if another process created the
      // destination after the initial exists check.
      fs.linkSync(tempPath, absolutePath);
      fs.unlinkSync(tempPath);
    }
  } catch (error) {
    try { fs.rmSync(tempPath, { force: true }); } catch { /* best effort */ }
    fail(`could not safely write ${filePath}: ${error.message}`);
  }
}

function runNano(file, output, force) {
  if (!file) fail('nano: missing input file');
  const stat = fs.statSync(file);
  if (!stat.isFile()) fail('nano: input must be a regular file');
  const input = fs.readFileSync(file);
  const name = Buffer.from(path.basename(file), 'utf8');
  const header = Buffer.alloc(HEADER_FIXED + name.length);
  MAGIC.copy(header, 0);
  header.writeUInt32BE(name.length, MAGIC.length);
  header.writeBigUInt64BE(BigInt(input.length), MAGIC.length + 4);
  name.copy(header, HEADER_FIXED);
  const compressed = zlib.deflateSync(input, { level: 9 });
  const outPath = output || `${file}.nano`;
  safeWrite(outPath, Buffer.concat([header, compressed]), force);
  console.log(`nano: ${file} (${input.length} B) -> ${outPath} [compression only; not encrypted]`);
  console.log(`nano: artifact icon ${path.resolve(__dirname, '../public/craft-icons/compressed-only.webp')}`);
}

function runMacro(file, output, force) {
  if (!file) fail('macro: missing .nano package');
  const pkg = fs.readFileSync(file);
  if (pkg.length < HEADER_FIXED || !pkg.subarray(0, MAGIC.length).equals(MAGIC)) {
    fail('not a supported .nano package (bad magic or truncated header)');
  }
  const nameLength = pkg.readUInt32BE(MAGIC.length);
  const expectedSize = pkg.readBigUInt64BE(MAGIC.length + 4);
  if (nameLength === 0 || nameLength > 4096 || HEADER_FIXED + nameLength >= pkg.length) {
    fail('invalid .nano package header');
  }
  const name = pkg.subarray(HEADER_FIXED, HEADER_FIXED + nameLength).toString('utf8');
  if (!name || name === '.' || name === '..' || path.basename(name) !== name || name.includes('/') || name.includes('\\')) {
    fail('unsafe filename in .nano package');
  }
  let outputBytes;
  try {
    outputBytes = zlib.inflateSync(pkg.subarray(HEADER_FIXED + nameLength));
  } catch (error) {
    fail(`invalid compressed payload: ${error.message}`);
  }
  if (BigInt(outputBytes.length) !== expectedSize) fail('inflated size does not match package header');
  const outPath = output || name;
  safeWrite(outPath, outputBytes, force);
  console.log(`macro: ${file} -> ${outPath} (${outputBytes.length} B) [inflated; no decryption performed]`);
}

function runProduction(args) {
  const distCli = path.resolve(__dirname, '../dist/cjs/lib/craft/cli/index.js');
  if (!fs.existsSync(distCli)) fail('production CLI is not built; run npm run build:lib first');
  process.argv = [process.execPath, distCli, ...args];
  require(distCli);
}

const args = process.argv.slice(2);
const command = args[0];
if (!command || command === '--help' || command === '-h' || command === 'help') {
  console.log('Craft Engine — compression and encryption are separate operations');
  console.log('  craft nano <file> [-o output.nano] [-f]      Compress only');
  console.log('  craft macro <file.nano> [-o output] [-f]     Inflate only');
  console.log('  craft craft <file> -p <passphrase>           Encrypt with production archive format');
  console.log('  craft uncraft <file.craft> -p <passphrase>   Decrypt production archive');
  console.log('  craft legacy-nano <file> -p <passphrase>     Former encrypted nano command');
  console.log('  craft legacy-macro <file.craft> -p <passphrase> Former encrypted macro command');
  console.log('  craft doctor | verify | watch | passkey | ... Existing production utilities');
} else if (command === 'nano' || command === 'macro') {
  const { positional, output, force } = parseOptions(args.slice(1));
  if (positional.length !== 1) fail(`usage: craft ${command} <file${command === 'macro' ? '.nano' : ''}> [-o output] [-f]`);
  if (command === 'nano') runNano(positional[0], output, force);
  else runMacro(positional[0], output, force);
} else if (command === 'craft' || command === 'uncraft') {
  const legacyCommand = command === 'craft' ? 'nano' : 'macro';
  runProduction([legacyCommand, ...args.slice(1)]);
} else if (command === 'legacy-nano' || command === 'legacy-macro') {
  runProduction([command === 'legacy-nano' ? 'nano' : 'macro', ...args.slice(1)]);
} else {
  // Keep existing auxiliary commands (doctor, verify, passkey, streaming, etc.)
  // intact; only the four primary command names acquire their clarified roles.
  runProduction(args);
}
