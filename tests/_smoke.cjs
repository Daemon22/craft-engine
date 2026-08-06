/* throwaway smoke debug — delete after */
const { Readable } = require('stream');
const { createHash } = require('crypto');
const fs = require('fs');
const m = require('../dist/cjs/lib/craft/index.js');
console.log('module loaded');

const PP = 'correct-horse-battery-staple';
const data = Buffer.from('Hello, CRAFT! '.repeat(10000)); // ~1.4 MB
const out = 'tests\\.v4dbg.craft';

function withTimeout(p, ms, label) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('TIMEOUT ' + label + ' after ' + ms + 'ms')), ms);
    p.then(v => { clearTimeout(t); resolve(v); }, e => { clearTimeout(t); reject(e); });
  });
}

(async () => {
  // 1. Stage 1+3 without self-verify
  try {
    const r = await withTimeout(m.nanoStream(Readable.from([data]), 'dbg.bin', 'application/octet-stream', PP, { output: out, chunkSize: 4096, verify: false }), 10000, 'nanoStream-verify-off');
    console.log('nanoStream(verify:false) ok: bytes', r.bytesProcessed, 'chunks', r.chunksProcessed, 'file exists?', fs.existsSync(out));
  } catch (e) { console.log('nanoStream(verify:false) threw:', e.message); return; }

  // 2. self-verify path: macroStream(path, verifyOnly)
  try {
    const v = await withTimeout(m.macroStream(out, PP, { verifyOnly: true }), 10000, 'macroStream-verifyOnly-path');
    console.log('macroStream(verifyOnly,path): iv', v.integrityVerified, 'bytes', v.bytesRestored, 'chunks', v.chunksRead);
  } catch (e) { console.log('macroStream(verifyOnly,path) threw:', e.message); }

  // 3. macroStream(buf, verifyOnly)
  try {
    const bb = fs.readFileSync(out);
    const v2 = await withTimeout(m.macroStream(bb, PP, { verifyOnly: true }), 8000, 'macroStream-verifyOnly-buf');
    console.log('macroStream(verifyOnly,buf): iv', v2.integrityVerified, 'chunks', v2.chunksRead);
  } catch (e) { console.log('macroStream(verifyOnly,buf) threw:', e.message); }

  // 4. full nanoStream WITH self-verify
  try {
    const r = await withTimeout(m.nanoStream(Readable.from([data]), 'dbg2.bin', 'application/octet-stream', PP, { output: out + '.full', chunkSize: 4096 }), 15000, 'nanoStream-full');
    console.log('nanoStream(full self-verify): iv', r.integrityVerified, 'bytes', r.bytesProcessed, 'chunks', r.chunksProcessed);
  } catch (e) { console.log('nanoStream-full threw:', e.message); return; }

  // 5. macroStream(path) full restore
  try {
    const x = await withTimeout(m.macroStream(out + '.full', PP), 12000, 'macroStream-full-path');
    console.log('macroStream(path) restore: len', x.buffer.length, 'iv', x.integrityVerified, 'identical?', x.buffer.equals(data), 'sha', createHash('sha256').update(x.buffer).digest('hex') === x.metadata.originalChecksum);
  } catch (e) { console.log('macroStream-full-path threw:', e.message); }
})().catch(e => console.log('TOPERR', e.stack));
console.log('queue scheduled');
