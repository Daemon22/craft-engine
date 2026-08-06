const fs = require('fs');
const s = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8');
const lines = s.split('\n');
const i = lines.findIndex(l => /function cmdBenchmark/.test(l));
for (let j = i; j < i + 6; j++) console.log((j + 1) + '|' + lines[j]);
