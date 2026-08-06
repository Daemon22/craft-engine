const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
for (let j = 585; j < 627; j++) console.log((j + 1) + '|' + lines[j]);
