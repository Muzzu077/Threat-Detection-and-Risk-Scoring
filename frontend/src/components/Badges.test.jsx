import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { RiskBadge, SeverityBadge, StatusBadge, AttackTypeBadge, RiskBar } from './Badges';

describe('RiskBadge', () => {
  it('renders LOW label and class for score < 31', () => {
    const { container } = render(<RiskBadge score={20} />);
    const span = container.querySelector('span');
    expect(span).toHaveClass('badge', 'badge-low');
    expect(span.textContent).toBe('LOW');
  });

  it('renders CRITICAL label and class for score >= 85', () => {
    const { container } = render(<RiskBadge score={92} />);
    const span = container.querySelector('span');
    expect(span).toHaveClass('badge-critical');
    expect(span.textContent).toBe('CRITICAL');
  });

  it('handles missing score by treating as 0', () => {
    const { container } = render(<RiskBadge />);
    expect(container.querySelector('span').textContent).toBe('LOW');
  });
});

describe('SeverityBadge', () => {
  it('uppercases the label', () => {
    const { container } = render(<SeverityBadge severity="high" />);
    expect(container.querySelector('span').textContent).toBe('HIGH');
  });
  it('defaults to LOW when missing', () => {
    const { container } = render(<SeverityBadge />);
    expect(container.querySelector('span').textContent).toBe('LOW');
  });
});

describe('StatusBadge', () => {
  it('renders status uppercase', () => {
    const { container } = render(<StatusBadge status="resolved" />);
    expect(container.querySelector('span').textContent).toBe('RESOLVED');
  });
  it('defaults to OPEN when missing', () => {
    const { container } = render(<StatusBadge />);
    expect(container.querySelector('span').textContent).toBe('OPEN');
  });
});

describe('AttackTypeBadge', () => {
  it('maps known attack types to classes', () => {
    const { container: c1 } = render(<AttackTypeBadge type="sql_injection" />);
    expect(c1.querySelector('span')).toHaveClass('badge-critical');

    const { container: c2 } = render(<AttackTypeBadge type="brute_force" />);
    expect(c2.querySelector('span')).toHaveClass('badge-high');
  });

  it('falls back to badge-low for unknown types', () => {
    const { container } = render(<AttackTypeBadge type="something_weird" />);
    expect(container.querySelector('span')).toHaveClass('badge-low');
  });

  it('handles missing type', () => {
    const { container } = render(<AttackTypeBadge />);
    expect(container.querySelector('span').textContent).toContain('UNKNOWN');
  });
});

describe('RiskBar', () => {
  it('renders the rounded score', () => {
    const { container } = render(<RiskBar score={73.4} />);
    expect(container.textContent).toContain('73');
  });
  it('renders 0 for missing score', () => {
    const { container } = render(<RiskBar />);
    expect(container.textContent).toContain('0');
  });
});
