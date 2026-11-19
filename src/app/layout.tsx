import type { ReactNode } from 'react';
import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Craft Engine',
  description: 'Craft — adaptive compression & encryption.',
  icons: {
    icon: '/craft-icons/compressed-encrypted.webp',
    apple: '/craft-icons/apple-touch-icon.png',
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
