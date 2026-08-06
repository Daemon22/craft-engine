const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
function rng(a, b) { for (let j = a; j <= b; j++) if (j in lines) console.log((j + 1) + '|' + lines[j]); }
rng(70, 95);
