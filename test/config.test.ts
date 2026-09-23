import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { environmentsOf, parseConfig } from '../src/config/load.js';

const example = readFileSync(new URL('../examples/phoenix/csp.yml', import.meta.url), 'utf8');

const minimal = (documents: string, extra = '') => `version: 1\n${extra}\ndocuments:\n${documents}`;

describe('parseConfig', () => {
  it('accepts the Phoenix example and applies defaults', () => {
    const result = parseConfig(example);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.settings.require_reason).toBe('medium');
    expect(result.config.settings.dev_environments).toEqual(['dev']);
    expect(environmentsOf(result.config)).toEqual(['dev', 'prod', 'staging']);
  });

  it('defaults mode to report-only', () => {
    const result = parseConfig(minimal('  app:\n    routes: ["/"]\n'));
    expect(result.ok && result.config.documents.app?.mode).toBe('report-only');
  });

  it('reports schema errors with their line', () => {
    const result = parseConfig(minimal('  app:\n    routes: ["/"]\n    directives:\n      scirpt-src: [self]\n'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]?.line).toBe(7);
  });

  it('requires a reason for accepted sources', () => {
    const result = parseConfig(
      minimal('  app:\n    routes: ["/"]\n    directives:\n      script-src:\n        - value: unsafe-inline\n          status: accepted\n'),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]?.message).toMatch(/requires a reason/);
  });

  it('rejects unknown quoted keywords', () => {
    const result = parseConfig(minimal(`  app:\n    routes: ["/"]\n    directives:\n      script-src: ["'unsafe-everything'"]\n`));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]).toMatchObject({ message: expect.stringMatching(/unknown CSP keyword/), line: 7 });
  });

  it('rejects undefined variables and variables missing an environment', () => {
    const result = parseConfig(
      minimal(
        '  app:\n    routes: ["/"]\n    directives:\n      connect-src: ["https://${API}", "https://${CDN}"]\n',
        'variables:\n  API:\n    dev: localhost\n    prod: api.example.com\n  OTHER:\n    prod: x.example.com\n',
      ),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const messages = result.errors.map((e) => e.message);
    expect(messages).toContain('variable OTHER has no value for environment "dev"');
    expect(messages).toContain('undefined variable ${CDN}');
  });

  it('rejects a route owned by two documents', () => {
    const result = parseConfig(minimal('  a:\n    routes: ["/x"]\n  b:\n    routes: ["/x"]\n'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors[0]?.message).toBe('route /x already belongs to document "a"');
  });
});
