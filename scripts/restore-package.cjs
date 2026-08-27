const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const packagePath = path.join(root, 'package.json');
const targetPath = path.join(root, 'node_modules', '@manya', 'craft-codec');
const backupPath = path.join(os.tmpdir(), `craft-engine-package-${crypto.createHash('sha256').update(root).digest('hex').slice(0, 16)}.json`);

if (fs.existsSync(backupPath)) {
  fs.copyFileSync(backupPath, packagePath);
  fs.rmSync(backupPath, { force: true });
}
fs.rmSync(targetPath, { recursive: true, force: true });
const sourcePath = path.join(root, 'craft-codec');
if (fs.existsSync(sourcePath)) {
  fs.symlinkSync(path.relative(path.dirname(targetPath), sourcePath), targetPath, 'dir');
}
console.log('Restored development package manifest after publication.');
