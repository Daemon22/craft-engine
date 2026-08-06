const { createReadStream } = require('fs');
const { readExact } = require('../dist/cjs/lib/craft/streamCore.js');

(async () => {
  const s = createReadStream('tests/_smoke.out', { highWaterMark: 64 * 1024 });
  console.log('created stream, paused?', s.readableFlowing, 'ended?', s.readableEnded);
  const p = readExact(s, 7);
  p.then(b => console.log('readExact ok len', b.length, b.toString('hex').slice(0,14)), e => console.log('readExact err', e.message));
  setTimeout(() => { s.destroy(); console.log('still hanging after 3s'); }, 3000);
})();
