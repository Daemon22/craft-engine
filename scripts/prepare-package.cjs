const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const packagePath = path.join(root, 'package.json');
const sourcePath = path.join(root, 'craft-codec');
const targetPath = path.join(root, 'node_modules', '@manya', 'craft-codec');
const backupPath = path.join(os.tmpdir(), `craft-engine-package-${crypto.createHash('sha256').update(root).digest('hex').slice(0, 16)}.json`);

const manifest = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
const codecManifest = JSON.parse(fs.readFileSync(path.join(sourcePath, 'package.json'), 'utf8'));
if (manifest.dependencies?.['@manya/craft-codec'] !== 'file:./craft-codec') {
  throw new Error('Expected development dependency @manya/craft-codec to use file:./craft-codec');
}
fs.writeFileSync(backupPath, JSON.stringify(manifest, null, 2) + '\n');
fs.mkdirSync(path.dirname(targetPath), { recursive: true });
fs.rmSync(targetPath, { recursive: true, force: true });
fs.cpSync(sourcePath, targetPath, { recursive: true });
fs.rmSync(path.join(targetPath, 'node_modules'), { recursive: true, force: true });
manifest.dependencies['@manya/craft-codec'] = `^${codecManifest.version}`;
delete manifest.workspaces;
fs.writeFileSync(packagePath, JSON.stringify(manifest, null, 2) + '\n');
console.log(`Prepared bundled @manya/craft-codec@${codecManifest.version} for publication.`);
