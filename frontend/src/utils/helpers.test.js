import { describe, it, expect } from 'vitest';
import {
  getSeverity,
  getSeverityColor,
  getRiskClass,
  truncate,
} from './helpers';

describe('getSeverity', () => {
  it('classifies low risk', () => {
    expect(getSeverity(0)).toBe('low');
    expect(getSeverity(30)).toBe('low');
  });
  it('classifies medium at 31', () => {
    expect(getSeverity(31)).toBe('medium');
    expect(getSeverity(60)).toBe('medium');
  });
  it('classifies high at 61', () => {
    expect(getSeverity(61)).toBe('high');
    expect(getSeverity(84)).toBe('high');
  });
  it('classifies critical at 85', () => {
    expect(getSeverity(85)).toBe('critical');
    expect(getSeverity(100)).toBe('critical');
  });
});

describe('getRiskClass', () => {
  it('returns the corresponding class at every boundary', () => {
    expect(getRiskClass(0)).toBe('risk-low');
    expect(getRiskClass(31)).toBe('risk-medium');
    expect(getRiskClass(61)).toBe('risk-high');
    expect(getRiskClass(85)).toBe('risk-critical');
  });
});

describe('getSeverityColor', () => {
  it('returns a hex for known severity', () => {
    expect(getSeverityColor('critical')).toMatch(/^#/);
    expect(getSeverityColor('high')).toMatch(/^#/);
    expect(getSeverityColor('medium')).toMatch(/^#/);
    expect(getSeverityColor('low')).toMatch(/^#/);
  });
  it('returns a default for unknown severity', () => {
    expect(getSeverityColor('unknown')).toMatch(/^#/);
  });
});

describe('truncate', () => {
  it('returns short strings unchanged', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });
  it('truncates long strings with ellipsis', () => {
    expect(truncate('abcdefghij', 5)).toBe('abcde…');
  });
  it('handles null / undefined gracefully', () => {
    expect(truncate(null)).toBe('');
    expect(truncate(undefined)).toBe('');
  });
});
