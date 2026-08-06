// Detached vitest launcher — survives parent shell expiry.
const { spawn } = require('child_process');
const fs = require('fs');
const out = fs.openSync(process.argv[2], 'w');
const files = process.argv.slice(3);
const child = spawn(
  process.platform === 'win32' ? 'npx.cmd' : 'npx',
  ['vitest', 'run', '--retry', '0', '--reporter=verbose', '--test-timeout=90000', ...files],
  { cwd: process.cwd(), stdio: [process.stdin, out, out], detached: true, windowsHide: true },
);
child.unref();
fs.closeSync(out);
fs.writeFileSync(process.argv[2] + '.pid', String(child.pid));
console.log('detached vitest pid', child.pid, '->', process.argv[2]);
