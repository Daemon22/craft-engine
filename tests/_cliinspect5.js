const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
const i = lines.findIndex(l => /function cmdPeek/.test(l));
console.log('=== cmdPeek @ ' + (i + 1) + ' ===');
for (let j = i; j < i + 26; j++) console.log((j + 1) + '|' + lines[j]);
const c = lines.findIndex(l => l.includes('case \'peek\''));
console.log('--- switch peek/cmdVerify ---');
for (let j = c; j < c + 30; j++) console.log((j + 1) + '|' + lines[j]);
