import { substituteVariables, type ConfigPath } from '../config/load.js';
import type { Config, DirectivesConfig } from '../config/schema.js';
import { parseSourceValue, type SourceValue } from './values.js';

export interface PolicySource {
  value: SourceValue;
  status?: 'pending' | 'accepted';
  reason?: string;
  devOnly: boolean;
  /** Location in csp.yml; absent for policies parsed from a header. */
  path?: ConfigPath;
}

export interface Policy {
  document: string;
  env: string;
  mode: 'report-only' | 'enforce';
  routes: string[];
  directives: Map<string, PolicySource[]>;
  /** Directives added by the tool (reporting), not written by the user. */
  reportEndpoint?: { group: string; url: string };
}

/** Builds the effective policy of one document in one environment: common + document, variables substituted. */
export function resolvePolicy(config: Config, documentName: string, env: string): Policy {
  const doc = config.documents[documentName];
  if (!doc) throw new Error(`unknown document "${documentName}"`);

  const includeDev = config.settings.dev_environments.includes(env);
  const directives = new Map<string, PolicySource[]>();

  const add = (source: DirectivesConfig, base: ConfigPath) => {
    for (const [directive, entries] of Object.entries(source)) {
      const list = directives.get(directive) ?? [];
      directives.set(directive, list);
      entries.forEach((entry, i) => {
        const obj = typeof entry === 'string' ? { value: entry } : entry;
        if (obj.dev_only && !includeDev) return;
        const value = parseSourceValue(substituteVariables(obj.value, config, env), directive);
        const existing = list.findIndex((s) => s.value.text === value.text);
        const resolved: PolicySource = {
          value,
          status: obj.status,
          reason: obj.reason,
          devOnly: obj.dev_only ?? false,
          path: [...base, directive, i],
        };
        // A document entry overrides the metadata of the same value in common.
        if (existing >= 0) list[existing] = resolved;
        else list.push(resolved);
      });
    }
  };

  add(config.common, ['common']);
  add(doc.directives, ['documents', documentName, 'directives']);

  const report = config.settings.report;
  return {
    document: documentName,
    env,
    mode: doc.mode,
    routes: doc.routes,
    directives,
    reportEndpoint: report ? { group: report.group, url: report.endpoint } : undefined,
  };
}

export interface Header {
  name: string;
  value: string;
}

export function policyHeaderName(mode: Policy['mode']): string {
  return mode === 'enforce' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
}

export function toHeaders(policy: Policy): Header[] {
  const parts = [...policy.directives].map(([directive, sources]) =>
    [directive, ...sources.map((s) => s.value.text)].join(' '),
  );
  const headers: Header[] = [];
  if (policy.reportEndpoint) {
    const { group, url } = policy.reportEndpoint;
    if (!policy.directives.has('report-uri')) parts.push(`report-uri ${url}`);
    if (!policy.directives.has('report-to')) parts.push(`report-to ${group}`);
    headers.push({ name: 'Reporting-Endpoints', value: `${group}="${url}"` });
  }
  headers.unshift({ name: policyHeaderName(policy.mode), value: parts.join('; ') });
  return headers;
}

/** Parses a CSP header value (possibly several comma-separated policies) into policies. */
export function parseHeaderPolicies(
  headerValue: string,
  meta: { document: string; env: string; mode: Policy['mode'] },
): Policy[] {
  return headerValue
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((policyText) => {
      const directives = new Map<string, PolicySource[]>();
      for (const part of policyText.split(';')) {
        const [name, ...values] = part.trim().split(/\s+/);
        if (!name) continue;
        const directive = name.toLowerCase();
        // Per spec, a repeated directive is ignored.
        if (directives.has(directive)) continue;
        directives.set(
          directive,
          values.map((v) => ({ value: safeParse(v, directive), devOnly: false })),
        );
      }
      return { ...meta, routes: [], directives };
    });
}

function safeParse(raw: string, directive: string): SourceValue {
  try {
    return parseSourceValue(raw, directive);
  } catch {
    return { kind: 'token', text: raw };
  }
}
