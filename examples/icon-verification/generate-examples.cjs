#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { encryptAsync, decryptAsync } = require('../../dist/cjs/lib/craft/codec.js');
const { getCraftArtifactIconForFile } = require('../../dist/cjs/lib/craft/artifact-icons.js');

const root = path.resolve(__dirname, '../..');
const samplePath = path.join(__dirname, 'sample.txt');
const compressedPath = path.join(__dirname, 'compressed-only.nano');
const encryptedOnlyPath = path.join(__dirname, 'encryption-only.encdemo');
const combinedPath = path.join(__dirname, 'compressed-and-encrypted.craft');
const demoPassphrase = 'CraftEngine-Icon-Demo-Only-NotForUse';

const sampleText = [
  'Craft Engine artifact icon verification sample.',
  'This repeated line gives the compression-only and combined examples useful payloads.',
  ...Array.from({ length: 24 }, (_, index) => `sample row ${String(index + 1).padStart(2, '0')}: repeatable demo content for icon verification.`),
  '',
].join('\n');
fs.writeFileSync(samplePath, sampleText, 'utf8');

function runCli(args) {
  const result = spawnSync(process.execPath, [path.join(root, 'bin/craft.js'), ...args], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status !== 0) throw new Error(`CLI command failed: ${args.join(' ')}`);
}

async function main() {
  runCli(['nano', samplePath, '-o', compressedPath, '--force']);
  runCli(['craft', samplePath, '-p', demoPassphrase, '-o', combinedPath, '--force']);

  // This authenticated JSON envelope uses the engine's AES-256-GCM/PBKDF2 codec
  // without compression, but is intentionally NOT a production .craft package.
  const plain = Buffer.from(sampleText, 'utf8');
  const encrypted = await encryptAsync(plain, demoPassphrase);
  const restored = await decryptAsync(
    encrypted.encrypted,
    demoPassphrase,
    encrypted.iv,
    encrypted.authTag,
    encrypted.salt,
  );
  if (!restored.equals(plain)) throw new Error('Encryption-only demo failed its round-trip verification.');

  const envelope = {
    format: 'craft-engine-icon-verification-encrypted-only-demo',
    version: 1,
    originalName: path.basename(samplePath),
    compression: 'none',
    encryption: {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2-SHA256',
      iterations: 600000,
      salt: encrypted.salt.toString('base64'),
      iv: encrypted.iv.toString('base64'),
      authTag: encrypted.authTag.toString('base64'),
      ciphertext: encrypted.encrypted.toString('base64'),
    },
    warning: 'Icon-verification demo only. Not a production Craft archive; uncraft cannot read this file.',
  };
  fs.writeFileSync(encryptedOnlyPath, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');

  for (const filename of [compressedPath, encryptedOnlyPath, combinedPath]) {
    const icon = getCraftArtifactIconForFile(filename);
    if (!icon) throw new Error(`No artifact icon mapped for ${path.basename(filename)}.`);
    console.log(`${path.basename(filename)} -> ${icon.publicPath} (${icon.label}${icon.supported ? '' : '; demo only'})`);
  }

  console.log(`Demo-only passphrase for encrypted samples: ${demoPassphrase}`);
  console.log('Do not use the public demo passphrase or fixtures to protect real data.');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
