'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Activity, Archive, ArrowDownToLine, ArrowRight, Check, ChevronDown, CircleHelp, FileArchive, FileUp, Fingerprint, Layers3, LockKeyhole, ShieldCheck, Sparkles, Zap } from 'lucide-react';

type Mode = 'nano' | 'macro';

function Dashboard() {
  const router = useRouter();
  const isDemo = useSearchParams().get('demo') === 'true';
  const [mode, setMode] = useState<Mode>('nano');
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { if (!isDemo) router.replace('/login'); }, [isDemo, router]);
  if (!isDemo) return null;

  function changeMode(next: Mode) {
    setMode(next); setFile(null); setPassphrase(''); setMessage('');
    if (inputRef.current) inputRef.current.value = '';
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || passphrase.length < 12) return;
    setBusy(true); setMessage('');
    try {
      const data = new FormData(); data.append('file', file); data.append('passphrase', passphrase);
      const response = await fetch(`/api/craft/${mode}`, { method: 'POST', body: data });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || 'Something went wrong. Please try again.');
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const originalName = response.headers.get('X-Craft-Original-Name');
      let downloadName = file.name.replace(/\.craft$/i, '') || 'restored-file';
      if (originalName) { try { downloadName = decodeURIComponent(originalName); } catch { /* use fallback */ } }
      link.href = url; link.download = mode === 'nano' ? `${file.name.endsWith('.craft') ? file.name : `${file.name}.craft`}` : downloadName;
      link.click(); URL.revokeObjectURL(url);
      setMessage(mode === 'nano' ? 'Your archive is ready and downloading.' : 'Your file has been restored and is downloading.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Something went wrong. Please try again.'); }
    finally { setBusy(false); }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="/?demo=true"><span className="brand-mark"><Layers3 size={21}/></span><span>craft<span className="brand-light">engine</span><small>ARCHIVE WITH INTENTION</small></span></a>
      <div className="nav-label">WORKSPACE</div>
      <nav aria-label="Main navigation"><a className="nav-item active" href="#overview"><Activity size={17}/> Overview <span className="nav-dot"/></a><a className="nav-item" href="#archive"><Archive size={17}/> Archive workspace</a><a className="nav-item" href="#activity"><Fingerprint size={17}/> Integrity activity</a></nav>
      <div className="sidebar-bottom"><div className="sidebar-note"><ShieldCheck size={19}/><div><strong>Built for peace of mind</strong><p>Every archive is verified for fidelity.</p></div></div><div className="sidebar-version"><span>CRAFT ENGINE</span><span>v0.2.0</span></div></div>
    </aside>
    <main className="main" id="overview">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>Overview</strong></div><div className="top-right"><span className="demo-pill"><span/> Demo workspace</span><a className="help-link" href="https://github.com/Daemon22/craft-engine" aria-label="Open Craft Engine on GitHub"><CircleHelp size={19}/></a><span className="avatar">AD</span><span className="profile">Azura Daemon<small>Demo account</small></span><ChevronDown size={15} className="muted"/></div></header>
      <div className="content">
        <div className="heading-row"><div><div className="eyebrow"><span/> YOUR ARCHIVAL WORKSPACE</div><h1>Good to see you <span>✳</span></h1><p>Everything you need to keep your data safe, in one place.</p></div><span className="system-status"><span/> Demo environment</span></div>
        <div className="section-heading"><div><h2>Workspace overview</h2><p>A snapshot of your archive activity.</p></div><span className="sample-label">SAMPLE DATA</span></div>
        <div className="stats-grid">
          {[{label:'Integrity scans',value:'1,204',note:'Files checked',icon:ShieldCheck,color:'cyan'}, {label:'Space saved',value:'4.2 GB',note:'With adaptive compression',icon:Zap,color:'violet'}, {label:'Active vaults',value:'3',note:'Across your workspace',icon:LockKeyhole,color:'amber'}, {label:'Engine uptime',value:'99.9%',note:'Reliable by design',icon:Activity,color:'green'}].map(({label,value,note,icon:Icon,color})=><div className="stat-card" key={label}><div className="stat-top"><span>{label}</span><span className={`stat-icon ${color}`}><Icon size={17}/></span></div><strong>{value}</strong><small>{note}</small></div>)}
        </div>
        <div className="workspace-grid"><section className="panel archive-panel" id="archive"><div className="panel-heading"><div><div className="panel-kicker"><Sparkles size={14}/> THE CRAFT WORKSPACE</div><h2>Make space for what matters.</h2><p>Protect your files with compression and encryption.</p></div><span className="panel-icon"><Archive size={21}/></span></div>
          <div className="tabs" role="tablist" aria-label="Archive action"><button type="button" role="tab" aria-selected={mode==='nano'} onClick={()=>changeMode('nano')}><FileArchive size={16}/> Create archive</button><button type="button" role="tab" aria-selected={mode==='macro'} onClick={()=>changeMode('macro')}><ArrowDownToLine size={16}/> Restore file</button></div>
          <form onSubmit={submit}><div className="form-intro"><div><h3>{mode==='nano'?'Create a secure archive':'Restore an archive'}</h3><p>{mode==='nano'?'Choose a file to compress and protect.':'Choose a .craft file and enter its passphrase.'}</p></div><span className="step">{mode==='nano'?'NANO':'MACRO'} MODE</span></div>
            <label className="dropzone" htmlFor="archive-file" onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault(); setFile(e.dataTransfer.files[0] || null); setMessage('');}}><span className="upload-icon"><FileUp size={22}/></span><strong>{file ? file.name : <>Drop your file here, or <span>browse</span></>}</strong><small>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB · Click to change file` : mode==='nano'?'Any file type · Maximum 100 MB':'.craft files · Maximum 100 MB'}</small></label>
            <input ref={inputRef} id="archive-file" className="visually-hidden" type="file" accept={mode==='macro'?'.craft':undefined} onChange={e=>{setFile(e.target.files?.[0] || null); setMessage('');}} required={!file}/>
            <div className="field-heading"><label htmlFor="passphrase">Passphrase</label><span>Minimum 12 characters</span></div><input id="passphrase" className="password" type="password" placeholder="Enter a strong passphrase" value={passphrase} onChange={e=>setPassphrase(e.target.value)} minLength={12} required autoComplete="off"/>
            <button className="primary-button" disabled={busy || !file || passphrase.length < 12} type="submit">{busy?'Processing…':mode==='nano'?'Craft secure archive':'Restore file'} <ArrowRight size={17}/></button>{message && <p className="form-message" role="status">{message}</p>}
          </form><div className="security-note"><ShieldCheck size={16}/> Encrypted with AES-256-GCM <span>•</span> Verified for integrity</div>
        </section>
        <aside className="right-column"><section className="panel strategy-panel"><div className="side-heading"><div><h2>Strategy performance</h2><p>Compression methods at work</p></div><span className="mini-badge">DEMO</span></div><div className="strategy-list">{[{name:'Brotli Q11',value:45,color:'blue'}, {name:'Zstd L22',value:32,color:'mint'}, {name:'Craft-Codec',value:18,color:'purple'}, {name:'Other strategies',value:5,color:'gold'}].map(item=><div className="strategy" key={item.name}><div><span><i className={item.color}/>{item.name}</span><strong>{item.value}%</strong></div><div className="track"><span className={item.color} style={{width:`${item.value}%`}}/></div></div>)}</div><div className="strategy-footer"><Sparkles size={15}/><span>Adaptive compression selects the best strategy for your data.</span></div></section>
          <section className="panel activity-panel" id="activity"><div className="side-heading"><div><h2>Integrity activity</h2><p>Recent sample checks</p></div><Fingerprint size={19} className="muted"/></div><div className="activity-row"><span className="check-icon"><Check size={14}/></span><div><strong>archive_2026_prod.craft</strong><small>Integrity verified</small></div><span className="activity-time">PASSED</span></div><div className="activity-row"><span className="check-icon"><Check size={14}/></span><div><strong>database_backup_v2.craft</strong><small>Integrity verified</small></div><span className="activity-time">PASSED</span></div><div className="activity-row"><span className="scan-icon"><Activity size={14}/></span><div><strong>assets_vault.craft</strong><small>Checking integrity</small></div><span className="activity-time scanning">SCANNING</span></div></section>
        </aside></div><footer><span>Crafted for data that matters.</span><span>SECURE BY DESIGN <span className="footer-dot">●</span> BUILT FOR FIDELITY</span></footer>
      </div>
    </main>
  </div>;
}

export default function Page() { return <Suspense><Dashboard /></Suspense>; }
