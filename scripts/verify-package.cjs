#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const root = path.resolve(__dirname, '..');
const required = [
  'dist/cjs/lib/index.js',
  'dist/cjs/lib/craft/index.js',
  'dist/esm/lib/index.js',
  'dist/esm/lib/craft/index.js',
  'dist/types/lib/index.d.ts',
  'dist/types/lib/craft/index.d.ts',
  'bin/craft.js',
];
for (const relative of required) {
  if (!fs.existsSync(path.join(root, relative))) {
    throw new Error(`Missing package artifact: ${relative}`);
  }
}

const cjs = require(path.join(root, 'dist/cjs/lib/index.js'));
const cjsCraft = require(path.join(root, 'dist/cjs/lib/craft/index.js'));
for (const [name, mod] of [['CJS root', cjs], ['CJS craft', cjsCraft]]) {
  for (const exportName of ['nano', 'macro', 'checksum']) {
    if (typeof mod[exportName] !== 'function') {
      throw new Error(`${name} export ${exportName} is not callable`);
    }
  }
}

(async () => {
  const esm = await import(pathToFileURL(path.join(root, 'dist/esm/lib/index.js')).href);
  const esmCraft = await import(pathToFileURL(path.join(root, 'dist/esm/lib/craft/index.js')).href);
  for (const [name, mod] of [['ESM root', esm], ['ESM craft', esmCraft]]) {
    for (const exportName of ['nano', 'macro', 'checksum']) {
      if (typeof mod[exportName] !== 'function') {
        throw new Error(`${name} export ${exportName} is not callable`);
      }
    }
  }

  const bin = fs.readFileSync(path.join(root, 'bin/craft.js'), 'utf8');
  if (!bin.includes('dist/cjs/lib/craft/cli/index.js')) {
    throw new Error('CLI shim does not target the generated CJS CLI');
  }
  console.log('Package/export matrix verified: CJS, ESM, types, and CLI artifacts are present and loadable.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
