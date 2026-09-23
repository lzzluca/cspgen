import { environmentsOf } from '../config/load.js';
import type { Config, Priority } from '../config/schema.js';
import { parseHeaderPolicies, resolvePolicy, toHeaders, type Header, type Policy } from '../policy/policy.js';
import { atLeast, comparePriority, evaluate, type EvaluateOptions, type Warning } from '../rules/evaluate.js';

export interface ReportWarning extends Omit<Warning, 'source'> {
  /** Environments where this warning applies. */
  envs: string[];
  reason?: string;
}

export interface DocumentReport {
  document: string;
  routes: string[];
  mode: Policy['mode'];
  headers: { env: string; headers: Header[] }[];
  warnings: ReportWarning[];
}

export interface Report {
  target: string;
  documents: DocumentReport[];
  notes: string[];
}

export function reviewConfig(config: Config, target: string, onlyEnv?: string): Report {
  const envs = onlyEnv ? [onlyEnv] : environmentsOf(config);
  const options: EvaluateOptions = {
    requireReason: config.settings.require_reason,
    devEnvironments: config.settings.dev_environments,
  };
  const documents = Object.keys(config.documents).map((name) =>
    documentReport(envs.map((env) => resolvePolicy(config, name, env)), options),
  );
  return { target, documents, notes: [] };
}

export interface LiveCsp {
  enforced: string[];
  reportOnly: string[];
  meta: string[];
}

export function reviewLive(target: string, csp: LiveCsp): Report {
  const options: EvaluateOptions = { requireReason: 'medium' };
  const notes: string[] = [];
  const documents: DocumentReport[] = [];

  const addAll = (values: string[], label: string, mode: Policy['mode']) =>
    values.forEach((value) =>
      parseHeaderPolicies(value, { document: label, env: 'live', mode }).forEach((policy, i, all) => {
        policy.document = all.length > 1 ? `${label} #${i + 1}` : label;
        documents.push(documentReport([policy], options));
      }),
    );

  addAll(csp.enforced, 'enforced', 'enforce');
  addAll(csp.reportOnly, 'report-only', 'report-only');
  addAll(csp.meta, 'meta', 'enforce');

  if (csp.meta.length > 0) {
    notes.push('A policy is delivered via <meta>: frame-ancestors, report-uri, report-to and sandbox are ignored there, and it only applies after the tag is parsed. Prefer an HTTP header.');
  }
  if (documents.length === 0) {
    notes.push('No Content-Security-Policy found: the page has no CSP protection.');
  }
  if (csp.enforced.length + csp.meta.length === 0 && csp.reportOnly.length > 0) {
    notes.push('Only a Report-Only policy is present: nothing is actually blocked.');
  }
  return { target, documents, notes };
}

function documentReport(policies: Policy[], options: EvaluateOptions): DocumentReport {
  const first = policies[0]!;
  const merged = new Map<string, ReportWarning>();
  for (const policy of policies) {
    for (const { source, ...w } of evaluate(policy, options)) {
      const key = `${w.rule}|${w.directive}|${w.value ?? ''}`;
      const existing = merged.get(key);
      if (existing) existing.envs.push(policy.env);
      else merged.set(key, { ...w, envs: [policy.env], reason: source?.reason });
    }
  }
  return {
    document: first.document,
    routes: first.routes,
    mode: first.mode,
    headers: policies.map((p) => ({ env: p.env, headers: toHeaders(p) })),
    warnings: [...merged.values()].sort((a, b) => comparePriority(a.priority, b.priority)),
  };
}

export function unresolvedAtLeast(report: Report, threshold: Priority): ReportWarning[] {
  return report.documents.flatMap((d) => d.warnings.filter((w) => !w.accepted && atLeast(w.priority, threshold)));
}
