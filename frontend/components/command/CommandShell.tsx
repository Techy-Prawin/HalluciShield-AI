'use client';

import React, { useEffect, useMemo, useState } from 'react';
import styles from './command.module.css';
import { Sidebar, TopSystemBar } from './TopSystemBar';

function Environment() {
  const [mounted, setMounted] = useState(false);
  const particles = useMemo(
    () =>
      Array.from({ length: 26 }, (_, i) => ({
        id: i,
        left: Math.round(2 + Math.random() * 96),
        size: Math.round(1 + Math.random() * 1.4) % 3,
        duration: Math.round(16 + Math.random() * 22),
        delay: -Math.round(Math.random() * 24),
      })),
    []
  );

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <div className="cc-environment" aria-hidden="true">
      <span className="env-floor" />
      <span className="env-circuit c1" />
      <span className="env-circuit c2" />
      <span className="env-circuit c3" />
      <span className="env-glow g1" />
      <span className="env-glow g2" />
      <span className="env-glow g3" />
      {mounted &&
        particles.map((p) => (
          <span
            key={p.id}
            className="env-particle"
            style={{
              left: `${p.left}%`,
              width: p.size,
              height: p.size,
              animationDuration: `${p.duration}s`,
              animationDelay: `${p.delay}s`,
              bottom: '-4px',
            }}
          />
        ))}
    </div>
  );
}

export function CommandShell({ children }: { children: React.ReactNode }) {
  return (
    <div className={styles.shell}>
      <Environment />
      <TopSystemBar />
      <div className={styles.shellBody}>
        <Sidebar />
        <main className={styles.main}>{children}</main>
      </div>
    </div>
  );
}