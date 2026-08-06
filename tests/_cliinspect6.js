const fs = require('fs');
const lines = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8').split('\n');
const hits = ['function verifyOneFile', 'function runVerifyScan', 'function cmdVerify', 'function cmdWatch', "runOnce()"];
for (const h of hits) {
  const i = lines.findIndex(l => l.includes(h));
  console.log('=== ' + h + ' @ ' + (i + 1) + ' ===');
  for (let j = i; j < i + 20; j++) if (j < lines.length) console.log((j + 1) + '|' + lines[j]);
}
