import type { Priority } from '../config/schema.js';
import type { Policy, PolicySource } from '../policy/policy.js';
import { isDevSource } from '../policy/values.js';

// Deterministic evaluation of a policy against the strictest possible CSP.
// Same policy in, same warnings out: no LLM involved here.

export interface Warning {
  rule: string;
  priority: Priority;
  directive: string;
  /** The offending source as written in the header; absent for missing directives. */
  value?: string;
  message: string;
  source?: PolicySource;
  accepted: boolean;
  /** Priority is at or above require_reason and nobody accepted it yet. */
  needsReason: boolean;
}

export interface EvaluateOptions {
  requireReason: Priority;
  /**
   * Environments where localhost-like sources are expected. In any other environment they are
   * flagged unless marked dev_only. Omit to skip the check (e.g. reviewing a live header).
   */
  devEnvironments?: string[];
}

const RANK: Record<Priority, number> = { low: 1, medium: 2, high: 3 };

export function atLeast(priority: Priority, threshold: Priority): boolean {
  return RANK[priority] >= RANK[threshold];
}

export function comparePriority(a: Priority, b: Priority): number {
  return RANK[b] - RANK[a];
}

/** Fetch directives fall back to others when absent (CSP3 §6.8.3). */
const FALLBACKS: Record<string, string[]> = {
  'script-src': ['script-src', 'default-src'],
  'style-src': ['style-src', 'default-src'],
  'object-src': ['object-src', 'default-src'],
  'img-src': ['img-src', 'default-src'],
  'font-src': ['font-src', 'default-src'],
  'connect-src': ['connect-src', 'default-src'],
  'media-src': ['media-src', 'default-src'],
  'manifest-src': ['manifest-src', 'default-src'],
  'frame-src': ['frame-src', 'child-src', 'default-src'],
  'worker-src': ['worker-src', 'child-src', 'script-src', 'default-src'],
};

/** The sources that actually govern a directive, following the fallback chain. */
export function effective(policy: Policy, directive: string) {
  for (const candidate of FALLBACKS[directive] ?? [directive]) {
    const sources = policy.directives.get(candidate);
    if (sources) return { directive: candidate, sources };
  }
  return undefined;
}

/** A reason is a human decision: it accepts the source unless the tool marked it pending. */
export function isAccepted(source: PolicySource | undefined): boolean {
  if (!source) return false;
  return source.status === 'accepted' || (source.reason !== undefined && source.status !== 'pending');
}

const hasKeyword = (sources: PolicySource[], keyword: string) =>
  sources.some((s) => s.value.kind === 'keyword' && s.value.keyword === keyword);
const hasNonceOrHash = (sources: PolicySource[]) =>
  sources.some((s) => s.value.kind === 'nonce' || s.value.kind === 'hash');

export function evaluate(policy: Policy, options: EvaluateOptions): Warning[] {
  const warnings = new Map<string, Warning>();

  const warn = (w: Omit<Warning, 'accepted' | 'needsReason'>) => {
    const key = `${w.directive}|${w.value ?? ''}|${w.rule}`;
    const valueKey = `${w.directive}|${w.value ?? ''}`;
    // One warning per directive/value: keep the most severe.
    for (const [k, existing] of warnings) {
      if (w.value === undefined || !k.startsWith(`${valueKey}|`)) continue;
      if (RANK[existing.priority] >= RANK[w.priority]) return;
      warnings.delete(k);
    }
    const accepted = isAccepted(w.source);
    warnings.set(key, { ...w, accepted, needsReason: !accepted && atLeast(w.priority, options.requireReason) });
  };

  const script = effective(policy, 'script-src');
  if (!script) {
    warn({
      rule: 'script-src-missing',
      priority: 'high',
      directive: 'script-src',
      message: 'neither script-src nor default-src is set: any script can run',
    });
  } else {
    const strictDynamic = hasKeyword(script.sources, 'strict-dynamic');
    const nonced = hasNonceOrHash(script.sources);
    for (const source of script.sources) {
      const v = source.value;
      const base = { directive: script.directive, value: v.text, source };
      if (v.kind === 'keyword' && v.keyword === 'unsafe-inline') {
        if (nonced) {
          warn({ ...base, rule: 'script-unsafe-inline-fallback', priority: 'low', message: "'unsafe-inline' is ignored by modern browsers because a nonce or hash is present; it only serves old browsers" });
        } else {
          warn({ ...base, rule: 'script-unsafe-inline', priority: 'high', message: "'unsafe-inline' allows any inline script, including injected ones: use nonces" });
        }
      } else if (v.kind === 'keyword' && v.keyword === 'unsafe-eval') {
        warn({ ...base, rule: 'script-unsafe-eval', priority: 'high', message: "'unsafe-eval' allows eval() and new Function(): strings become code" });
      } else if (v.kind === 'wildcard' || v.kind === 'scheme') {
        warn({ ...base, rule: 'script-wildcard', priority: 'high', message: `${v.text} allows scripts from any host` });
      } else if (strictDynamic) {
        // With 'strict-dynamic', CSP3 browsers ignore host allowlists and 'self'.
        continue;
      } else if (v.kind === 'host') {
        warn({ ...base, rule: 'script-external-host', priority: 'medium', message: `scripts from ${v.text} run with full access: CDNs and JSONP endpoints can be used to bypass the policy` });
      } else if (v.kind === 'keyword' && v.keyword === 'self') {
        warn({ ...base, rule: 'script-self', priority: 'low', message: "'self' allows any script served by your origin, including uploaded files or JSONP endpoints" });
      }
    }
  }

  const object = effective(policy, 'object-src');
  if (!object) {
    warn({ rule: 'object-src-missing', priority: 'high', directive: 'object-src', message: "object-src is not set: plugins (<object>, <embed>) can load code; set object-src 'none'" });
  } else if (!(object.sources.length === 1 && hasKeyword(object.sources, 'none'))) {
    const via = object.directive === 'object-src' ? '' : ` (falls back to ${object.directive})`;
    warn({ rule: 'object-src-not-none', priority: 'high', directive: 'object-src', message: `object-src${via} allows plugins (<object>, <embed>) that can run code; set object-src 'none'` });
  }

  if (!policy.directives.has('base-uri')) {
    warn({ rule: 'base-uri-missing', priority: 'high', directive: 'base-uri', message: "base-uri is not set: an injected <base> tag can redirect relative script URLs; set base-uri 'none' or 'self'" });
  }

  const style = effective(policy, 'style-src');
  if (style) {
    const nonced = hasNonceOrHash(style.sources);
    for (const source of style.sources) {
      if (source.value.kind === 'keyword' && source.value.keyword === 'unsafe-inline') {
        warn({
          directive: style.directive,
          value: source.value.text,
          source,
          rule: nonced ? 'style-unsafe-inline-fallback' : 'style-unsafe-inline',
          priority: nonced ? 'low' : 'medium',
          message: nonced
            ? "'unsafe-inline' is ignored by modern browsers because a nonce or hash is present"
            : "'unsafe-inline' in styles allows CSS injection (data exfiltration, UI redressing)",
        });
      }
    }
  }

  for (const [directive, sources] of policy.directives) {
    for (const source of sources) {
      const v = source.value;
      const base = { directive, value: v.text, source };
      if (v.kind === 'keyword' && v.keyword === 'unsafe-hashes') {
        warn({ ...base, rule: 'unsafe-hashes', priority: 'medium', message: "'unsafe-hashes' allows inline event handlers (onclick=...): move them to scripts" });
      }
      const devEnv = options.devEnvironments?.includes(policy.env) ?? true;
      if (!devEnv && isDevSource(v) && !source.devOnly) {
        warn({ ...base, rule: 'dev-source-outside-dev', priority: 'medium', message: `${v.text} looks like a development source but is not marked dev_only, so it ships to ${policy.env}` });
      }
      if (directive === 'script-src' || directive === 'style-src' || directive === 'object-src') continue;
      if (v.kind === 'host') {
        warn({ ...base, rule: 'external-host', priority: 'low', message: `external host ${v.text}` });
      } else if (v.kind === 'wildcard' || (v.kind === 'scheme' && v.scheme !== 'data' && v.scheme !== 'blob')) {
        warn({ ...base, rule: 'wildcard-source', priority: 'low', message: `${v.text} allows any host for ${directive}` });
      }
    }
  }

  const styleExplicit = policy.directives.get('style-src');
  for (const source of styleExplicit ?? []) {
    if (source.value.kind === 'host') {
      warn({ directive: 'style-src', value: source.value.text, source, rule: 'external-host', priority: 'low', message: `external host ${source.value.text}` });
    }
  }

  return [...warnings.values()].sort((a, b) => comparePriority(a.priority, b.priority));
}
