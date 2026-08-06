const fs = require('fs');
const s = fs.readFileSync('src/lib/craft/cli/index.ts', 'utf8');
const lines = s.split('\n');
function show(pat) {
  const re = new RegExp(pat);
  const i = lines.findIndex(l => re.test(l));
  console.log('--- /' + pat + '/  first@line ' + (i + 1) + ' ---');
  const start = Math.max(0, i - 1);
  const end = Math.min(lines.length - 1, i + 14);
  for (let j = start; j <= end; j++) console.log((j + 1) + '|' + lines[j]);
}
for (const p of [
  'parseArgs',
  'switch\\(command\\)',
  'case .nano.:',
  'case .macro.:',
  'case .peek.:',
  'case .verify.:',
  'function cmdNano',
  'function cmdMacro',
  'function cmdPeek',
  'function cmdVerify',
  'function cmdBenchmark',
  'case .version.:',
  'function parseArgs',
  'opts.force',
  'opts.passphrase',
]) show(p);
console.log('TOTAL LINES:', lines.length);
