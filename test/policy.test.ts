import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config/load.js';
import type { Config } from '../src/config/schema.js';
import { parseHeaderPolicies, resolvePolicy, toHeaders } from '../src/policy/policy.js';
import { parseSourceValue } from '../src/policy/values.js';

const example = readFileSync(new URL('../examples/phoenix/csp.yml', import.meta.url), 'utf8');
const load = (source: string): Config => {
  const result = parseConfig(source);
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.config;
};

describe('parseSourceValue', () => {
  it('accepts keywords with or without quotes', () => {
    expect(parseSourceValue('self', 'script-src').text).toBe("'self'");
    expect(parseSourceValue("'self'", 'script-src').text).toBe("'self'");
  });

  it('turns the nonce keyword into a placeholder', () => {
    expect(parseSourceValue('nonce', 'script-src').text).toBe("'nonce-{NONCE}'");
  });

  it('classifies schemes, hosts and wildcards', () => {
    expect(parseSourceValue('https:', 'script-src')).toMatchObject({ kind: 'scheme', scheme: 'https' });
    expect(parseSourceValue('wss://api.example.com:443/x', 'connect-src')).toMatchObject({ kind: 'host', host: 'api.example.com' });
    expect(parseSourceValue('*', 'img-src').kind).toBe('wildcard');
  });

  it('keeps token directives verbatim', () => {
    expect(parseSourceValue('allow-scripts', 'sandbox')).toEqual({ kind: 'token', text: 'allow-scripts' });
  });
});

describe('resolvePolicy', () => {
  const config = load(example);

  it('merges common and document directives and substitutes variables', () => {
    const policy = resolvePolicy(config, 'learning', 'prod');
    const connect = policy.directives.get('connect-src')!.map((s) => s.value.text);
    expect(connect).toEqual(["'self'", 'wss://api.example.com']);
    expect(policy.directives.get('object-src')!.map((s) => s.value.text)).toEqual(["'none'"]);
  });

  it('includes dev_only sources only in dev environments', () => {
    const dev = resolvePolicy(config, 'learning', 'dev').directives.get('connect-src')!;
    expect(dev.map((s) => s.value.text)).toContain('ws://localhost:4000');
  });

  it('lets a document override the metadata of a common value', () => {
    const cfg = load(`version: 1
common:
  script-src: [self]
documents:
  app:
    routes: ["/"]
    directives:
      script-src:
        - value: "'self'"
          reason: needed
`);
    const script = resolvePolicy(cfg, 'app', 'default').directives.get('script-src')!;
    expect(script).toHaveLength(1);
    expect(script[0]?.reason).toBe('needed');
  });
});

describe('toHeaders', () => {
  it('uses the header matching the mode and adds reporting', () => {
    const config = load(example);
    const [csp, reporting] = toHeaders(resolvePolicy(config, 'admin', 'prod'));
    expect(csp?.name).toBe('Content-Security-Policy-Report-Only');
    expect(csp?.value).toContain("script-src 'self' https://cdn.tiny.cloud");
    expect(csp?.value).toMatch(/report-to csp-endpoint$/);
    expect(reporting).toEqual({
      name: 'Reporting-Endpoints',
      value: 'csp-endpoint="https://o123.ingest.sentry.io/api/456/security/?sentry_key=abc"',
    });
  });
});

describe('parseHeaderPolicies', () => {
  it('splits comma-separated policies and ignores repeated directives', () => {
    const policies = parseHeaderPolicies("script-src 'self'; script-src *, object-src 'none'", {
      document: 'x',
      env: 'live',
      mode: 'enforce',
    });
    expect(policies).toHaveLength(2);
    expect(policies[0]!.directives.get('script-src')!.map((s) => s.value.text)).toEqual(["'self'"]);
  });
});
