'use client';

import { signIn } from 'next-auth/react';
import { ArrowRight, Layers3, ShieldCheck } from 'lucide-react';
import Link from 'next/link';

export default function LoginPage() {
  return <main className="login-page"><div className="login-card"><div className="login-brand"><span className="brand-mark"><Layers3 size={22}/></span> craft<span>engine</span></div><div className="login-icon"><ShieldCheck size={28}/></div><div className="eyebrow"><span/> YOUR DATA, PROTECTED</div><h1>A little more peace of mind.</h1><p>Secure, high-density archival for the files that matter most.</p><button className="github-button" onClick={() => signIn('github')}>Sign in with GitHub <ArrowRight size={17}/></button><div className="login-divider"><span/> or explore first <span/></div><Link className="demo-button" href="/?demo=true">Explore demo workspace <ArrowRight size={17}/></Link><small>Compression. Encryption. Confidence.</small></div></main>;
}
