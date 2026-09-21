import React from 'react';

export type IconName =
  | 'shield'
  | 'scan'
  | 'crosshair'
  | 'layers'
  | 'brain'
  | 'gauge'
  | 'hexagon'
  | 'network'
  | 'chart'
  | 'settings'
  | 'bell'
  | 'clock'
  | 'activity'
  | 'upload'
  | 'lock'
  | 'alert'
  | 'check'
  | 'chevronRight'
  | 'chevronDown'
  | 'globe'
  | 'cpu'
  | 'db'
  | 'cloud'
  | 'code'
  | 'zap'
  | 'refresh'
  | 'play'
  | 'wrench'
  | 'eye'
  | 'box'
  | 'filter'
  | 'route'
  | 'terminal'
  | 'spark'
  | 'user'
  | 'menu'
  | 'close'
  | 'server'
  | 'flask'
  | 'function'
  | 'target'
  | 'bug'
  | 'pulse'
  | 'folder'
  | 'link'
  | 'download'
  | 'aster';

const PATHS: Record<IconName, React.ReactNode> = {
  shield: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  scan: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.35-4.35" />
      <path d="M11 8a3 3 0 015.2 2.1" strokeDasharray="2 2" />
    </>
  ),
  crosshair: (
    <>
      <circle cx="12" cy="12" r="7" />
      <path d="M12 2v4M12 18v4M2 12h4M18 12h4" />
    </>
  ),
  layers: (
    <>
      <path d="M12 2L2 7l10 5 10-5-10-5z" />
      <path d="M2 12l10 5 10-5" />
      <path d="M2 17l10 5 10-5" />
    </>
  ),
  brain: (
    <>
      <path d="M9.5 2A2.5 2.5 0 017 4.5v.55M9.5 2a2.5 2.5 0 012.5 2.5V21M9.5 2H7a3 3 0 000 6M9.5 2a4.5 4.5 0 11.02 0z" />
      <path d="M7 6a3 3 0 000 6M15.5 2a2.5 2.5 0 012.5 2.5v.55M17 6a3 3 0 000 6M12 21V9.5" />
    </>
  ),
  gauge: (
    <>
      <path d="M12 14l4.5-4.5" />
      <path d="M3.3 18a9 9 0 1117.4 0" />
      <circle cx="12" cy="14" r="1.5" fill="currentColor" stroke="none" />
    </>
  ),
  hexagon: <path d="M12 2l8.5 5v10L12 22l-8.5-5V7L12 2z" />,
  network: (
    <>
      <circle cx="6" cy="5" r="2.2" />
      <circle cx="18" cy="5" r="2.2" />
      <circle cx="12" cy="12" r="2.2" />
      <circle cx="6" cy="19" r="2.2" />
      <circle cx="18" cy="19" r="2.2" />
      <path d="M6 7v9.8M18 7v9.8M8.2 6h7.6M6 17h12M13.6 12h-3.2" />
    </>
  ),
  chart: (
    <>
      <path d="M4 20V10M10 20V4M16 20v-8M22 20H2" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 00.34 1.87l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.7 1.7 0 00-1.87-.34 1.7 1.7 0 00-1 1.55V21a2 2 0 11-4 0v-.09a1.7 1.7 0 00-1.11-1.55 1.7 1.7 0 00-1.87.34l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.7 1.7 0 00.34-1.87 1.7 1.7 0 00-1.55-1H3a2 2 0 110-4h.09a1.7 1.7 0 001.55-1.11 1.7 1.7 0 00-.34-1.87l-.06-.06a2 2 0 112.83-2.83l.06.06a1.7 1.7 0 001.87.34h.01A1.7 1.7 0 0010 3.09V3a2 2 0 114 0v.09a1.7 1.7 0 001 1.55h.01a1.7 1.7 0 001.87-.34l.06-.06a2 2 0 112.83 2.83l-.06.06a1.7 1.7 0 00-.34 1.87v.01a1.7 1.7 0 001.55 1h.09a2 2 0 110 4h-.09a1.7 1.7 0 00-1.55 1z" />
    </>
  ),
  bell: (
    <>
      <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  activity: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
  upload: (
    <>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <path d="M17 8l-5-5-5 5M12 3v12" />
    </>
  ),
  lock: (
    <>
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 018 0v4" />
    </>
  ),
  alert: (
    <>
      <path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </>
  ),
  check: <path d="M20 6L9 17l-5-5" />,
  chevronRight: <path d="M9 18l6-6-6-6" />,
  chevronDown: <path d="M6 9l6 6 6-6" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a15 15 0 010 18 15 15 0 010-18z" />
    </>
  ),
  cpu: (
    <>
      <rect x="5" y="5" width="14" height="14" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
    </>
  ),
  db: (
    <>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" />
      <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </>
  ),
  cloud: <path d="M17.5 19a4.5 4.5 0 100-9 6 6 0 10-11 3.2" />,
  code: <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />,
  zap: <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />,
  refresh: (
    <>
      <path d="M21 12a9 9 0 11-2.64-6.36M21 3v6h-6" />
    </>
  ),
  play: <path d="M6 4l14 8-14 8V4z" />,
  wrench: (
    <>
      <path d="M14.7 6.3a1 1 0 000-1.4l-1.4-1.4a1 1 0 00-1.4 0l-1.6 1.6a5 5 0 00-6.9 6.9l7.8 7.8a2 2 0 002.8 0l4.3-4.3a2 2 0 000-2.8L14.7 6.3z" />
      <path d="M14.7 6.3l3-3" />
    </>
  ),
  eye: (
    <>
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  box: (
    <>
      <path d="M21 8l-9-5-9 5v8l9 5 9-5V8z" />
      <path d="M3 8l9 5 9-5M12 13v8" />
    </>
  ),
  filter: <path d="M22 3H2l8 9.5V19l4 2v-8.5L22 3z" />,
  route: <path d="M4 5h10a2 2 0 012 2v10a2 2 0 002 2h2M4 5h2M4 5l3 0M20 19h-2M20 19l-3 0" />,
  terminal: <path d="M4 17l6-6-6-6M12 19h8" />,
  spark: <path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9L19 15z" />,
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0116 0" />
    </>
  ),
  menu: <path d="M3 6h18M3 12h18M3 18h18" />,
  close: <path d="M18 6L6 18M6 6l12 12" />,
  server: (
    <>
      <rect x="3" y="3" width="18" height="7" rx="2" />
      <rect x="3" y="14" width="18" height="7" rx="2" />
      <path d="M7 6.5h.01M7 17.5h.01" />
    </>
  ),
  flask: (
    <>
      <path d="M9 3h6M10 3v5.5L4.5 19a2 2 0 001.8 3h11.4a2 2 0 001.8-3L14 8.5V3" />
      <path d="M6.5 15h11" />
    </>
  ),
  function: <path d="M16 3l-8 18M9 8h10M5 16h10" />,
  target: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
    </>
  ),
  bug: (
    <>
      <path d="M8 2l4 3 4-3M4 8v4a8 8 0 0016 0V8M2 8h4M18 8h4M2 12h3M19 12h3M4 17l3-1M20 17l-3-1M12 11v5" />
    </>
  ),
  pulse: <path d="M2 12h4l3-8 4 16 3-8h6" />,
  folder: <path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />,
  link: <path d="M10 14a5 5 0 007 0l3-3a5 5 0 00-7-7l-1.5 1.5M14 10a5 5 0 00-7 0l-3 3a5 5 0 007 7l1.5-1.5" />,
  download: (
    <>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <path d="M7 10l5 5 5-5M12 15V3" />
    </>
  ),
  aster: <path d="M12 2v20M2 12h20M4.9 4.9l14.2 14.2M19.1 4.9L4.9 19.1" />,
};

interface IconProps {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
  style?: React.CSSProperties;
}

export function Icon({ name, size = 16, strokeWidth = 1.7, className, style }: IconProps) {
  return (
    <svg
      className={className}
      style={style}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}