'use client';

import { signIn } from 'next-auth/react';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
  const router = useRouter();

  const handleBypass = () => {
    // Temporary bypass for exploration
    router.push('/?demo=true');
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      fontFamily: 'system-ui, sans-serif',
      backgroundColor: '#0f172a',
      color: '#f8fafc'
    }}>
      <div style={{
        padding: '2rem',
        borderRadius: '1rem',
        backgroundColor: '#1e293b',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
        width: '100%',
        maxWidth: '400px',
        textAlign: 'center'
      }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 'bold', marginBottom: '1rem', color: '#38bdf8' }}>Craft Engine</h1>
        <p style={{ color: '#94a3b8', marginBottom: '2rem' }}>Secure, high-density archival suite.</p>

        <button
          onClick={() => signIn('github')}
          style={{
            width: '100%',
            padding: '0.75rem',
            backgroundColor: '#24292f',
            color: 'white',
            border: 'none',
            borderRadius: '0.5rem',
            fontSize: '1rem',
            fontWeight: '600',
            cursor: 'pointer',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem'
          }}
        >
          Sign in with GitHub
        </button>

        <div style={{ margin: '1rem 0', color: '#475569' }}>— or —</div>

        <button
          onClick={handleBypass}
          style={{
            width: '100%',
            padding: '0.75rem',
            backgroundColor: 'transparent',
            color: '#38bdf8',
            border: '1px solid #38bdf8',
            borderRadius: '0.5rem',
            fontSize: '1rem',
            fontWeight: '600',
            cursor: 'pointer'
          }}
        >
          Explore Demo Mode (Bypass)
        </button>
      </div>
    </div>
  );
}
