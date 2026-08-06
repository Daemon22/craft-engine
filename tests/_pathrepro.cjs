const fs = require('fs');
const m = require('../dist/cjs/lib/craft/index.js');
const PP = 'correct-horse-battery-staple';

function to(p, ms) { return Promise.race([p, new Promise((_,re)=>setTimeout(()=>re(new Error('TO '+ms)), ms))]); }

(async () => {
  const buf = fs.readFileSync('tests\\.v4dbg.craft');
  console.log('file size', buf.length);

  console.log('[buf verifyOnly] start');
  try { const r = await to(m.macroStream(buf, PP, { verifyOnly: true }), 5000); console.log('[buf verifyOnly] ok iv', r.integrityVerified, 'chunks', r.chunksRead); }
  catch (e) { console.log('[buf verifyOnly] ERR:', e.message); }

  console.log('[path verifyOnly] start');
  try { const r = await to(m.macroStream('tests\\.v4dbg.craft', PP, { verifyOnly: true }), 5000); console.log('[path verifyOnly] ok iv', r.integrityVerified, 'chunks', r.chunksRead); }
  catch (e) { console.log('[path verifyonly] ERR:', e.message); }

  console.log('[path full restore] start');
  try { const r = await to(m.macroStream('tests\\.v4dbg.craft', PP), 6000); const identical = r.buffer.equals(Buffer.from('Hello, CRAFT! '.repeat(10000))); console.log('[path full] ok len', r.buffer.length, 'iv', r.integrityVerified, 'identical', identical); }
  catch (e) { console.log('[path full] ERR:', e.message); }
})().catch(e=>console.log('TOP',e.stack));
