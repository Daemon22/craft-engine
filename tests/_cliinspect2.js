const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
function rng(a, b) { for (let j = a; j <= b; j++) console.log((j + 1) + '|' + lines[j]); }
console.log('//=== IMPORTS 14-70 ==='); rng(13, 70);
console.log('//=== cmdNano 188-245 ==='); rng(187, 245);
console.log('//=== cmdMacro 257-335 ==='); rng(256, 335);
console.log('//=== cmdPeek 334-432 ==='); rng(333, 432);
console.log('//=== cmdVerify/runVerifyScan 432-642 ==='); rng(431, 641);
