const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
const i = lines.findIndex(l => /function cmdVerify/.test(l));
for (let j = i; j < i + 18; j++) console.log((j + 1) + '|' + lines[j]);
const k = lines.findIndex(l => l.includes('case \'verify\''));
console.log('--- switch verify ---');
for (let j = k; j < k + 6; j++) console.log((j + 1) + '|' + lines[j]);
