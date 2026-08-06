'use strict';

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const standalone = path.join(root, '.next', 'standalone');
const staticDir = path.join(root, '.next', 'static');
const publicDir = path.join(root, 'public');

if (!fs.existsSync(standalone)) {
  throw new Error('.next/standalone missing — is output: "standalone" set in next.config?');
}

fs.cpSync(staticDir, path.join(standalone, '.next', 'static'), { recursive: true });
if (fs.existsSync(publicDir)) {
  fs.cpSync(publicDir, path.join(standalone, 'public'), { recursive: true });
}

console.log('Standalone bundle ready:', path.relative(root, standalone));
