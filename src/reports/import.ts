import { environmentsOf } from '../config/load.js';
import type { Config, Directive, DirectivesConfig } from '../config/schema.js';
import { DIRECTIVES } from '../config/schema.js';
import { resolvePolicy } from '../policy/policy.js';
import { documentForPath } from '../policy/routes.js';
import { parseSourceValue } from '../policy/values.js';
import { effective } from '../rules/evaluate.js';
import type { Violation } from './parse.js';

// Turns raw violation reports into proposals for csp.yml:
// drop noise, map each report to a document and a source, group duplicates.

export interface Proposal {
  document: string;
  directive: Directive;
  /** Source in csp.yml form, e.g. https://cdn.tiny.cloud, unsafe-inline, data: */
  source: string;
  count: number;
  /** A few blocked URLs, to show what the source covers. */
  examples: string[];
  /** Already allowed by the current policy: the report predates it or comes from a cached page. */
  alreadyAllowed: boolean;
}

export interface ImportAnalysis {
  total: number;
  /** Violations caused by browser extensions or the browser itself. */
  noise: number;
  /** Paths that no document route matches. */
  unmatched: Map<string, number>;
  /** Violations that cannot be mapped to a source (unknown directive or blocked value). */
  unsupported: number;
  proposals: Proposal[];
}

const EXTENSION = /^(chrome|moz|safari|safari-web|ms-browser)-extension:/i;
const MAX_EXAMPLES = 3;

export function analyzeViolations(config: Config, violations: Violation[]): ImportAnalysis {
  const analysis: ImportAnalysis = { total: violations.length, noise: 0, unmatched: new Map(), unsupported: 0, proposals: [] };
  const grouped = new Map<string, Proposal>();

  for (const v of violations) {
    if (isNoise(v)) {
      analysis.noise++;
      continue;
    }
    let documentUrl: URL;
    try {
      documentUrl = new URL(v.documentUrl);
    } catch {
      analysis.unsupported++;
      continue;
    }
    const document = documentForPath(config, documentUrl.pathname);
    if (!document) {
      analysis.unmatched.set(documentUrl.pathname, (analysis.unmatched.get(documentUrl.pathname) ?? 0) + 1);
      continue;
    }
    const directive = baseDirective(v.directive);
    const source = directive && toSource(v.blocked, documentUrl);
    if (!directive || !source) {
      analysis.unsupported++;
      continue;
    }

    const key = `${document}|${directive}|${source}`;
    const proposal = grouped.get(key) ?? { document, directive, source, count: 0, examples: [], alreadyAllowed: false };
    grouped.set(key, proposal);
    proposal.count++;
    if (proposal.examples.length < MAX_EXAMPLES && !proposal.examples.includes(v.blocked) && v.blocked !== source) {
      proposal.examples.push(v.blocked);
    }
  }

  for (const proposal of grouped.values()) proposal.alreadyAllowed = isAllowed(config, proposal);
  analysis.proposals = [...grouped.values()].sort((a, b) => b.count - a.count);
  return analysis;
}

function isNoise(v: Violation): boolean {
  return EXTENSION.test(v.blocked) || EXTENSION.test(v.sourceFile ?? '') || v.blocked.startsWith('about:');
}

/** Reports name the precise directive (script-src-elem); csp.yml usually uses the base one. */
function baseDirective(directive: string): Directive | undefined {
  const base = directive.toLowerCase().replace(/-(elem|attr)$/, '');
  return (DIRECTIVES as readonly string[]).includes(base) ? (base as Directive) : undefined;
}

const KEYWORD_BLOCKED: Record<string, string> = {
  inline: 'unsafe-inline',
  eval: 'unsafe-eval',
  'wasm-eval': 'wasm-unsafe-eval',
  self: 'self',
  data: 'data:',
  blob: 'blob:',
};

function toSource(blocked: string, documentUrl: URL): string | undefined {
  const keyword = KEYWORD_BLOCKED[blocked];
  if (keyword) return keyword;
  let url: URL;
  try {
    url = new URL(blocked);
  } catch {
    return undefined;
  }
  if (['data:', 'blob:', 'filesystem:', 'mediastream:'].includes(url.protocol)) return url.protocol;
  if (url.origin === documentUrl.origin) return 'self';
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return undefined;
  return `${url.protocol}//${url.host}`;
}

/** Whether the document's policy already allows the source in some environment. */
function isAllowed(config: Config, proposal: Proposal): boolean {
  const text = parseSourceValue(proposal.source, proposal.directive).text;
  return environmentsOf(config).some((env) => {
    const allowed = effective(resolvePolicy(config, proposal.document, env), proposal.directive);
    return allowed?.sources.some((s) => s.value.text === text) ?? false;
  });
}

/**
 * When a directive is set neither in the document nor in common, the browser falls back to
 * default-src. Adding the directive would drop that fallback, so its default-src values
 * must be copied over first.
 */
export function fallbackSeed(config: Config, document: string, directive: Directive): string[] {
  const doc = config.documents[document];
  if (!doc || directive in doc.directives || directive in config.common) return [];
  // Same merge as resolvePolicy: common first, then the document.
  const defaults: NonNullable<DirectivesConfig[Directive]> = [
    ...(config.common['default-src'] ?? []),
    ...(doc.directives['default-src'] ?? []),
  ];
  const seen = new Set<string>(["'none'"]);
  const seed: string[] = [];
  for (const entry of defaults) {
    if (typeof entry === 'object' && entry.dev_only) continue;
    const raw = typeof entry === 'string' ? entry : entry.value;
    const text = parseSourceValue(raw, 'default-src').text;
    if (seen.has(text)) continue;
    seen.add(text);
    seed.push(raw);
  }
  return seed;
}
