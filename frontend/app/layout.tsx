import type { Metadata } from 'next';
import './globals.css';
import { CommandCenterProvider } from '@/components/command/CommandCenterContext';

export const metadata: Metadata = {
  title: 'HalluciShield · AI Security Command Center',
  description:
    'Adaptive multi-agent command center for detecting and mitigating hallucination-induced software vulnerabilities in AI-generated code.',
  icons: {
    icon: '/icon.svg',
    shortcut: '/icon.svg',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <CommandCenterProvider>{children}</CommandCenterProvider>
      </body>
    </html>
  );
}