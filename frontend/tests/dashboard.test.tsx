import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import CommandCenter from '../components/command/CommandCenter';
import { CommandCenterProvider } from '../components/command/CommandCenterContext';

vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

vi.mock('next/link', () => ({
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  }) => <a href={typeof href === 'string' ? href : '/'} {...rest}>{children}</a>,
}));

describe('Command Center Dashboard', () => {
  it('renders the command center masthead, nav and preserved upload portal', () => {
    render(
      <CommandCenterProvider>
        <CommandCenter />
      </CommandCenterProvider>
    );

    expect(screen.getAllByText('HALLUCISHIELD').length).toBeGreaterThan(0);
    expect(screen.getByText((c) => c.includes('SECURE CODE'))).toBeDefined();

    // Preserved working functionality
    expect(screen.getByText('Repository Upload Portal')).toBeDefined();
    expect(screen.getByText(/Drag and drop a source code repository/i)).toBeDefined();
    expect(screen.getByText(/Zip Slip Protected/i)).toBeDefined();

    // Sidebar navigation
    expect(screen.getByText('Command Center')).toBeDefined();
    expect(screen.getAllByText('Threat Intelligence').length).toBeGreaterThan(0);
    expect(screen.getByText('Vulnerabilities')).toBeDefined();
    expect(screen.getByText('Runtime Defense')).toBeDefined();
    expect(screen.getAllByText('Adaptive Learning').length).toBeGreaterThan(0);
  });

  it('renders core command center panels', () => {
    render(
      <CommandCenterProvider>
        <CommandCenter />
      </CommandCenterProvider>
    );

    expect(screen.getByText('AI CORE ACTIVE')).toBeDefined();
    expect(screen.getByText('System Health')).toBeDefined();
    expect(screen.getByText('Confidence Metrics')).toBeDefined();
    expect(screen.getByText('Network Topology')).toBeDefined();
    expect(screen.getByText('SECURE REPOSITORY INGESTION')).toBeDefined();
  });
});