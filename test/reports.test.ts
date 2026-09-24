import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config/load.js';
import type { Config } from '../src/config/schema.js';
import { mergeObservations } from '../src/observations.js';
import { documentForPath, routeMatches } from '../src/policy/routes.js';
import { analyzeViolations, fallbackSeed } from '../src/reports/import.js';
import { parseReports, ReportFormatError, type Violation } from '../src/reports/parse.js';

const example = readFileSync(new URL('../examples/phoenix/csp.yml', import.meta.url), 'utf8');
const load = (source: string): Config => {
  const result = parseConfig(source);
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.config;
};
const config = load(example);

const legacy = { 'csp-report': { 'document-uri': 'https://app.example.com/admin/x', 'violated-directive': 'script-src-elem', 'blocked-uri': 'https://cdn.example.com/a.js' } };
const api = {
  type: 'csp-violation',
  url: 'https://app.example.com/learning/',
  body: { documentURL: 'https://app.example.com/learning/', effectiveDirective: 'img-src', blockedURL: 'https://img.example.com/x.png' },
};

describe('parseReports', () => {
  it('reads both report formats, arrays and single values', () => {
    const { violations, skipped } = parseReports(JSON.stringify([legacy, [api], { type: 'deprecation', body: {} }]));
    expect(violations).toEqual([
      { documentUrl: 'https://app.example.com/admin/x', directive: 'script-src-elem', blocked: 'https://cdn.example.com/a.js', sourceFile: undefined, disposition: undefined },
      { documentUrl: 'https://app.example.com/learning/', directive: 'img-src', blocked: 'https://img.example.com/x.png', sourceFile: undefined, disposition: undefined },
    ]);
    expect(skipped).toBe(1);
  });

  it('reads NDJSON', () => {
    expect(parseReports(`${JSON.stringify(legacy)}\n\n${JSON.stringify([api, api])}\n`).violations).toHaveLength(3);
  });

  it('reports the line of invalid NDJSON', () => {
    expect(() => parseReports(`${JSON.stringify(legacy)}\n{oops`)).toThrow(new ReportFormatError('line 2 is not valid JSON'));
  });
});

describe('routes', () => {
  it('matches exact paths, named segments and wildcards', () => {
    expect(routeMatches('/', '/')).toBe(true);
    expect(routeMatches('/', '/x')).toBe(false);
    expect(routeMatches('/products/:id', '/products/42')).toBe(true);
    expect(routeMatches('/products/:id', '/products/42/edit')).toBe(false);
    expect(routeMatches('/admin/*', '/admin/users/3')).toBe(true);
  });

  it('picks the most specific document', () => {
    const cfg = load(`version: 1
documents:
  site: { routes: ["/*"] }
  admin: { routes: ["/admin/*"] }
`);
    expect(documentForPath(cfg, '/admin/users')).toBe('admin');
    expect(documentForPath(cfg, '/about')).toBe('site');
  });
});

describe('analyzeViolations', () => {
  const v = (path: string, directive: string, blocked: string, sourceFile?: string): Violation => ({
    documentUrl: `https://app.example.com${path}`,
    directive,
    blocked,
    sourceFile,
  });

  it('groups duplicates, orders by count and keeps a few examples', () => {
    const analysis = analyzeViolations(config, [
      v('/learning/a', 'img-src', 'https://img.example.com/1.png'),
      v('/learning/b', 'img-src', 'https://img.example.com/2.png'),
      v('/admin/x', 'frame-src', 'https://player.example.com/embed'),
    ]);
    expect(analysis.proposals.map((p) => [p.document, p.directive, p.source, p.count])).toEqual([
      ['learning', 'img-src', 'https://img.example.com', 2],
      ['admin', 'frame-src', 'https://player.example.com', 1],
    ]);
    expect(analysis.proposals[0]!.examples).toEqual(['https://img.example.com/1.png', 'https://img.example.com/2.png']);
  });

  it('maps keywords, same-origin URLs and precise directives', () => {
    const analysis = analyzeViolations(config, [
      v('/admin/x', 'script-src-elem', 'inline'),
      v('/admin/x', 'script-src', 'eval'),
      v('/admin/x', 'img-src', 'data'),
      v('/admin/x', 'connect-src', 'https://app.example.com/api'),
      v('/admin/x', 'connect-src', 'wss://live.example.com:8443/socket'),
    ]);
    expect(analysis.proposals.map((p) => `${p.directive} ${p.source}`)).toEqual([
      'script-src unsafe-inline',
      'script-src unsafe-eval',
      'img-src data:',
      'connect-src self',
      'connect-src wss://live.example.com:8443',
    ]);
  });

  it('drops extension noise and counts pages outside every document', () => {
    const analysis = analyzeViolations(config, [
      v('/learning/', 'script-src-elem', 'chrome-extension://abc/x.js'),
      v('/learning/', 'style-src-attr', 'inline', 'moz-extension://abc/content.js'),
      v('/login', 'connect-src', 'https://api.example.com'),
      v('/admin/x', 'trusted-types-sink', 'trusted-types-sink'),
    ]);
    expect(analysis).toMatchObject({ noise: 2, unsupported: 1, proposals: [] });
    expect([...analysis.unmatched]).toEqual([['/login', 1]]);
  });

  it('marks sources the policy already allows in some environment', () => {
    const analysis = analyzeViolations(config, [
      v('/admin/x', 'script-src', 'https://cdn.tiny.cloud/1/tinymce.min.js'),
      v('/learning/', 'connect-src', 'wss://api.staging.example.com/socket'),
      v('/learning/', 'img-src', 'https://app.example.com/logo.png'),
    ]);
    expect(analysis.proposals.every((p) => p.alreadyAllowed)).toBe(true);
  });
});

describe('fallbackSeed', () => {
  it('copies default-src values when adding a directive that fell back to it', () => {
    const cfg = load(`version: 1
common:
  default-src: [none, "https://fonts.example.com"]
  img-src: [self]
documents:
  app:
    routes: ["/"]
    directives:
      default-src: [self, "https://cdn.example.com", { value: "http://localhost:4000", dev_only: true }]
`);
    expect(fallbackSeed(cfg, 'app', 'frame-src')).toEqual(['https://fonts.example.com', 'self', 'https://cdn.example.com']);
    expect(fallbackSeed(cfg, 'app', 'img-src')).toEqual([]);
  });

  it('seeds nothing when default-src is none', () => {
    expect(fallbackSeed(config, 'admin', 'frame-src')).toEqual([]);
  });
});

describe('mergeObservations', () => {
  it('sums counts for the same source and keeps examples short', () => {
    const at = new Date('2026-09-24T10:00:00Z');
    const proposal = { document: 'admin', directive: 'script-src' as const, source: 'https://x.example.com', count: 3, examples: ['a', 'b'], alreadyAllowed: false };
    const once = mergeObservations({ version: 1, observations: [] }, [proposal], 'production-report', at);
    const twice = mergeObservations(once, [{ ...proposal, count: 2, examples: ['c', 'd'] }], 'production-report', at);
    expect(twice.observations).toEqual([
      { document: 'admin', directive: 'script-src', source: 'https://x.example.com', count: 5, examples: ['a', 'b', 'c'], from: 'production-report', last_seen: at.toISOString() },
    ]);
  });
});
