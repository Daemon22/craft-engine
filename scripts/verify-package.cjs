#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const root = path.resolve(__dirname, '..');
const required = [
  'dist/cjs/lib/index.js',
  'dist/cjs/lib/craft/index.js',
  'dist/cjs/lib/craft/http-adapter.js',
  'dist/esm/lib/index.js',
  'dist/esm/lib/craft/index.js',
  'dist/esm/lib/craft/http-adapter.js',
  'dist/types/lib/index.d.ts',
  'dist/types/lib/craft/index.d.ts',
  'dist/types/lib/craft/http-adapter.d.ts',
  'bin/craft.js',
];
for (const relative of required) {
  if (!fs.existsSync(path.join(root, relative))) {
    throw new Error(`Missing package artifact: ${relative}`);
  }
}

const cjs = require(path.join(root, 'dist/cjs/lib/index.js'));
const cjsCraft = require(path.join(root, 'dist/cjs/lib/craft/index.js'));
const cjsAdapter = require(path.join(root, 'dist/cjs/lib/craft/http-adapter.js'));
const publicCjsAdapter = require('craft-engine/lib/craft/http-adapter');
for (const [name, mod] of [['CJS root', cjs], ['CJS craft', cjsCraft]]) {
  for (const exportName of ['nano', 'macro', 'checksum']) {
    if (typeof mod[exportName] !== 'function') {
      throw new Error(`${name} export ${exportName} is not callable`);
    }
  }
}
for (const [name, mod] of [['CJS adapter', cjsAdapter], ['published CJS adapter subpath', publicCjsAdapter]]) {
  if (typeof mod.createCraftHttpAdapter !== 'function') {
    throw new Error(`${name} does not export createCraftHttpAdapter`);
  }
}
if (typeof cjsCraft.createCraftHttpAdapter !== 'function') {
  throw new Error('CJS craft export does not include createCraftHttpAdapter');
}

(async () => {
  const esm = await import(pathToFileURL(path.join(root, 'dist/esm/lib/index.js')).href);
  const esmCraft = await import(pathToFileURL(path.join(root, 'dist/esm/lib/craft/index.js')).href);
  const esmAdapter = await import(pathToFileURL(path.join(root, 'dist/esm/lib/craft/http-adapter.js')).href);
  const publicEsmAdapter = await import('craft-engine/lib/craft/http-adapter');
  for (const [name, mod] of [['ESM root', esm], ['ESM craft', esmCraft]]) {
    for (const exportName of ['nano', 'macro', 'checksum']) {
      if (typeof mod[exportName] !== 'function') {
        throw new Error(`${name} export ${exportName} is not callable`);
      }
    }
  }
  for (const [name, mod] of [['ESM adapter', esmAdapter], ['published ESM adapter subpath', publicEsmAdapter]]) {
    if (typeof mod.createCraftHttpAdapter !== 'function') {
      throw new Error(`${name} does not export createCraftHttpAdapter`);
    }
  }
  if (typeof esmCraft.createCraftHttpAdapter !== 'function') {
    throw new Error('ESM craft export does not include createCraftHttpAdapter');
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
