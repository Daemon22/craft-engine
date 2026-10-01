'use client';

import React, { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function Dashboard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const isDemo = searchParams.get('demo') === 'true';

  // State for simulated stats
  const [stats, setStats] = useState({
    activeCrafts: 12,
    spaceSaved: '4.2 GB',
    health: 'Optimal',
    version: '0.2.0-harden'
  });

  if (!isDemo) {
    // In a real app, this would check the session
    // Redirecting to login if not in demo mode
    useEffect(() => {
      const timer = setTimeout(() => router.push('/login'), 100);
      return () => clearTimeout(timer);
    }, []);
    return <div style={{ backgroundColor: '#0f172a', minHeight: '100vh' }} />;
  }

  return (
    <div style={{
      fontFamily: 'system-ui, sans-serif',
      backgroundColor: '#0f172a',
      color: '#f8fafc',
      minHeight: '100vh',
      padding: '2rem'
    }}>
      {/* Top Header */}
      <header style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '3rem',
        borderBottom: '1px solid #1e293b',
        paddingBottom: '1rem'
      }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#38bdf8', margin: 0 }}>CRAFT <span style={{ fontWeight: '300', color: '#94a3b8' }}>Engine</span></h1>
          <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.2rem' }}>
            Environment: <span style={{ color: '#10b981' }}>{stats.health}</span> | v{stats.version}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>DEMO SESSION</div>
            <div style={{ fontSize: '0.9rem' }}>Azura Daemon</div>
          </div>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#38bdf8', display: 'flex', alignItems: 'center', justifySelf: 'center', fontWeight: 'bold' }}>
            <span style={{ width: '100%', textAlign: 'center' }}>AD</span>
          </div>
        </div>
      </header>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem', marginBottom: '3rem' }}>
        {[
          { label: 'Integrity Scans', value: '1,204', icon: '🛡️' },
          { label: 'Adaptive Savings', value: stats.spaceSaved, icon: '📉' },
          { label: 'Active Vaults', value: '3', icon: '🔐' },
          { label: 'Uptime', value: '99.9%', icon: '⚡' },
        ].map((stat, i) => (
          <div key={i} style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid #334155' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>{stat.icon}</div>
            <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>{stat.label}</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>{stat.value}</div>
          </div>
        ))}
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '2rem' }}>

        {/* Left Column: Nano & Macro Area */}
        <section>
          <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '1rem', marginBottom: '2rem', border: '1px solid #334155' }}>
            <h2 style={{ fontSize: '1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ color: '#38bdf8' }}>✦</span> Nano Archive Creator
            </h2>
            <div style={{
              border: '2px dashed #334155',
              borderRadius: '0.75rem',
              padding: '3rem',
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'border-color 0.2s'
            }}>
              <p style={{ color: '#94a3b8' }}>Drag files here or <b>browse</b> to craft a secure archive</p>
              <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '1rem' }}>
                Adaptive 12-strategy compression enabled (Brotli/Zstd/Craft-Codec)
              </div>
            </div>
            <div style={{ marginTop: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.5rem' }}>Passphrase (min 12 chars)</label>
              <input type="password" placeholder="••••••••••••" style={{
                width: '100%',
                padding: '0.75rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '0.5rem',
                color: 'white'
              }} />
            </div>
            <button style={{
              marginTop: '1.5rem',
              width: '100%',
              padding: '0.75rem',
              backgroundColor: '#38bdf8',
              color: '#0f172a',
              border: 'none',
              borderRadius: '0.5rem',
              fontWeight: 'bold',
              cursor: 'pointer'
            }}>CRAFT ARCHIVE</button>
          </div>

          <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '1rem', border: '1px solid #334155' }}>
            <h2 style={{ fontSize: '1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ color: '#f59e0b' }}>✦</span> Macro Restoration
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginBottom: '1rem' }}>Restore your files from <code>.craft</code> packages with guaranteed integrity.</p>
            <div style={{ display: 'flex', gap: '1rem' }}>
               <input type="file" style={{ display: 'none' }} id="restore-file" />
               <label htmlFor="restore-file" style={{
                 flex: 1,
                 padding: '0.75rem',
                 backgroundColor: '#0f172a',
                 border: '1px solid #334155',
                 borderRadius: '0.5rem',
                 cursor: 'pointer',
                 textAlign: 'center',
                 fontSize: '0.9rem'
               }}>Select .craft file</label>
               <button style={{
                 padding: '0.75rem 2rem',
                 backgroundColor: '#f59e0b',
                 color: '#0f172a',
                 border: 'none',
                 borderRadius: '0.5rem',
                 fontWeight: 'bold',
                 cursor: 'pointer'
               }}>RESTORE</button>
            </div>
          </div>
        </section>

        {/* Right Column: Engine Stats */}
        <aside>
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '1rem', border: '1px solid #334155' }}>
            <h3 style={{ fontSize: '1rem', marginBottom: '1rem', color: '#94a3b8' }}>Strategy Performance</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {[
                { name: 'Brotli Q11', usage: 45, color: '#38bdf8' },
                { name: 'Zstd L22', usage: 32, color: '#10b981' },
                { name: 'Craft-Codec', usage: 18, color: '#8b5cf6' },
                { name: 'Other (Delta/RLE)', usage: 5, color: '#f59e0b' }
              ].map((strat, i) => (
                <div key={i}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.4rem' }}>
                    <span>{strat.name}</span>
                    <span>{strat.usage}%</span>
                  </div>
                  <div style={{ height: '6px', backgroundColor: '#0f172a', borderRadius: '3px' }}>
                    <div style={{ width: `${strat.usage}%`, height: '100%', backgroundColor: strat.color, borderRadius: '3px' }}></div>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: '2rem', padding: '1rem', backgroundColor: '#0f172a', borderRadius: '0.5rem', fontSize: '0.75rem' }}>
              <div style={{ color: '#64748b', marginBottom: '0.5rem' }}>FIXITY CHECK LOG</div>
              <div style={{ color: '#10b981' }}>[OK] archive_2026_prod.craft</div>
              <div style={{ color: '#10b981' }}>[OK] database_backup_v2.craft</div>
              <div style={{ color: '#38bdf8' }}>[SCANNING] assets_vault.craft...</div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
