import { describe, expect, it } from 'vitest';
import { parseHeaderPolicies } from '../src/policy/policy.js';
import { evaluate, type EvaluateOptions } from '../src/rules/evaluate.js';
import { extractMetaCsp } from '../src/live.js';
import { reviewLive } from '../src/report/review.js';

const options: EvaluateOptions = { requireReason: 'medium', devEnvironments: ['dev'] };
const STRICT_BASE = "object-src 'none'; base-uri 'none'";

function warningsFor(header: string, env = 'prod') {
  const [policy] = parseHeaderPolicies(header, { document: 'app', env, mode: 'enforce' });
  return evaluate(policy!, options).map((w) => `${w.priority}:${w.rule}${w.value ? ` ${w.value}` : ''}`);
}

describe('evaluate', () => {
  it('finds nothing to warn about in a strict nonce policy', () => {
    expect(warningsFor(`script-src 'nonce-abc' 'strict-dynamic'; ${STRICT_BASE}`)).toEqual([]);
  });

  it('flags an empty policy', () => {
    expect(warningsFor('img-src *')).toEqual([
      'high:script-src-missing',
      'high:object-src-missing',
      'high:base-uri-missing',
      'low:wildcard-source *',
    ]);
  });

  it('rates unsafe-inline in scripts high and in styles medium', () => {
    const warnings = warningsFor(`script-src 'unsafe-inline'; style-src 'unsafe-inline'; ${STRICT_BASE}`);
    expect(warnings).toContain("high:script-unsafe-inline 'unsafe-inline'");
    expect(warnings).toContain("medium:style-unsafe-inline 'unsafe-inline'");
  });

  it("downgrades unsafe-inline when a nonce makes browsers ignore it", () => {
    expect(warningsFor(`script-src 'nonce-abc' 'unsafe-inline'; ${STRICT_BASE}`)).toEqual([
      "low:script-unsafe-inline-fallback 'unsafe-inline'",
    ]);
  });

  it('flags wildcards and schemes in script-src as high', () => {
    expect(warningsFor(`script-src https: data:; ${STRICT_BASE}`)).toEqual([
      'high:script-wildcard https:',
      'high:script-wildcard data:',
    ]);
  });

  it('rates external script hosts medium and self low, unless strict-dynamic', () => {
    expect(warningsFor(`script-src 'self' https://cdn.example.com; ${STRICT_BASE}`)).toEqual([
      'medium:script-external-host https://cdn.example.com',
      "low:script-self 'self'",
    ]);
    expect(warningsFor(`script-src 'nonce-a' 'strict-dynamic' 'self' https://cdn.example.com; ${STRICT_BASE}`)).toEqual([]);
  });

  it('falls back to default-src for scripts and keeps the most severe warning per value', () => {
    expect(warningsFor(`default-src https://cdn.example.com; base-uri 'none'`)).toEqual([
      'high:object-src-not-none',
      'medium:script-external-host https://cdn.example.com',
    ]);
  });

  it('flags development sources outside dev environments', () => {
    const header = `script-src 'nonce-a'; connect-src ws://localhost:4000; ${STRICT_BASE}`;
    expect(warningsFor(header, 'prod')).toContain('medium:dev-source-outside-dev ws://localhost:4000');
    expect(warningsFor(header, 'dev')).not.toContain('medium:dev-source-outside-dev ws://localhost:4000');
  });

  it('marks medium and high warnings as needing a reason', () => {
    const [policy] = parseHeaderPolicies(`script-src 'unsafe-eval'; img-src https://img.example.com; ${STRICT_BASE}`, {
      document: 'app',
      env: 'prod',
      mode: 'enforce',
    });
    const byRule = Object.fromEntries(evaluate(policy!, options).map((w) => [w.rule, w.needsReason]));
    expect(byRule).toEqual({ 'script-unsafe-eval': true, 'external-host': false });
  });
});

describe('reviewLive', () => {
  it('notes a missing policy, report-only-only and meta delivery', () => {
    expect(reviewLive('x', { enforced: [], reportOnly: [], meta: [] }).notes[0]).toMatch(/No Content-Security-Policy/);
    expect(reviewLive('x', { enforced: [], reportOnly: ["script-src 'self'"], meta: [] }).notes).toContainEqual(
      expect.stringMatching(/nothing is actually blocked/),
    );
    expect(reviewLive('x', { enforced: [], reportOnly: [], meta: ["script-src 'self'"] }).notes[0]).toMatch(/<meta>/);
  });

  it('extracts CSP from meta tags', () => {
    const html = `<head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="script-src &#39;self&#39;"></head>`;
    expect(extractMetaCsp(html)).toEqual(["script-src 'self'"]);
  });
});
