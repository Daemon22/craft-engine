export default function Home() {
  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem', maxWidth: '42rem', margin: '0 auto' }}>
      <h1>Craft Engine</h1>
      <p>
        Craft — adaptive compression & encryption. Upload a file to craft it (compress & encrypt)
        or restore a previously crafted file.
      </p>
      <ul>
        <li>
          <code>POST /api/craft/nano</code> — compress &amp; encrypt a file into a <code>.craft</code> package
        </li>
        <li>
          <code>POST /api/craft/macro</code> — decrypt &amp; restore a <code>.craft</code> package
        </li>
      </ul>
      <p>
        CLI: <code>craft nano &lt;file&gt; -p &lt;passphrase&gt;</code> and{' '}
        <code>craft macro &lt;file.craft&gt; -p &lt;passphrase&gt;</code>
      </p>
    </main>
  );
}
