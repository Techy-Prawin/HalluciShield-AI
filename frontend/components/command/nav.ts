import type { IconName } from '@/components/icons';

export interface NavItem {
  href: string;
  label: string;
  icon: IconName;
}

export const NAV_ITEMS: NavItem[] = [
  { href: '/dashboard', label: 'Command Center', icon: 'crosshair' },
  { href: '/threats', label: 'Threat Intelligence', icon: 'activity' },
  { href: '/vulnerabilities', label: 'Vulnerabilities', icon: 'bug' },
  { href: '/patches', label: 'Patch Intelligence', icon: 'wrench' },
  { href: '/reasoning', label: 'AI Reasoning', icon: 'brain' },
  { href: '/confidence', label: 'Confidence Engine', icon: 'gauge' },
  { href: '/learning', label: 'Adaptive Learning', icon: 'function' },
  { href: '/runtime', label: 'Runtime Defense', icon: 'zap' },
  { href: '/analytics', label: 'Analytics', icon: 'chart' },
  { href: '/system', label: 'System', icon: 'server' },
];

/** The multi-agent security pipeline wired around the AI Core. */
export interface AgentDef {
  id: string;
  label: string;
  icon: IconName;
  color: string;
}

export const AGENTS: AgentDef[] = [
  { id: 'hallucination', label: 'Hallucination Detection', icon: 'eye', color: 'var(--magenta)' },
  { id: 'security', label: 'Security Analysis', icon: 'shield', color: 'var(--red)' },
  { id: 'dependency', label: 'Dependency Analysis', icon: 'box', color: 'var(--sky)' },
  { id: 'risk', label: 'Risk Engine', icon: 'gauge', color: 'var(--amber)' },
  { id: 'patch', label: 'Patch Generation', icon: 'wrench', color: 'var(--green)' },
  { id: 'validation', label: 'Validation', icon: 'check', color: 'var(--cyan)' },
  { id: 'confidence', label: 'Confidence Engine', icon: 'target', color: 'var(--blue)' },
  { id: 'learning', label: 'Adaptive Learning', icon: 'function', color: 'var(--violet)' },
  { id: 'runtime', label: 'Runtime Monitoring', icon: 'pulse', color: 'var(--lime)' },
];

/** The DETECT → VALIDATE → REPAIR → LEARN doctrine labels for agents. */
export const AGENT_MISSION: Record<string, 'DETECT' | 'VALIDATE' | 'REPAIR' | 'LEARN'> = {
  hallucination: 'DETECT',
  security: 'DETECT',
  dependency: 'DETECT',
  risk: 'VALIDATE',
  patch: 'REPAIR',
  validation: 'VALIDATE',
  confidence: 'VALIDATE',
  learning: 'LEARN',
  runtime: 'DETECT',
};