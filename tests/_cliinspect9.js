const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
const i = lines.findIndex(l => l.includes('function runOnce'));
for (let j = i - 1; j < i + 14; j++) console.log((j + 1) + '|' + lines[j]);
