#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', 'dist', 'esm');

function filesIn(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? filesIn(full) : [full];
  });
}

for (const file of filesIn(root).filter((file) => file.endsWith('.js'))) {
  let source = fs.readFileSync(file, 'utf8');
  source = source.replace(/(['"])(\.\.?\/[^'"\n]+?)\1/g, (match, quote, specifier) => {
    if (specifier.endsWith('.js') || specifier.endsWith('.json') || specifier.endsWith('.mjs')) {
      return match;
    }
    const candidate = path.resolve(path.dirname(file), `${specifier}.js`);
    return fs.existsSync(candidate) ? `${quote}${specifier}.js${quote}` : match;
  });
  fs.writeFileSync(file, source);
}
