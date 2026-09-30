import type { FindingKind } from './candidates.js';

// Citation checks: string comparisons only, no second LLM. They prove the
// thing exists in the code, not that it matters for the CSP (that stays a
// judgment of the LLM, reviewed as a pending source).

export type Verification = { verified: true; line: number } | { verified: false; reason: string };

interface Claim {
  kind: FindingKind;
  source?: string;
  line: number;
  text: string;
}

const normalize = (s: string) => s.replace(/\s+/g, ' ').trim();

/** What the cited text must look like for each kind of finding. */
const KIND_SHAPE: Partial<Record<FindingKind, RegExp>> = {
  'inline-script': /<script\b/i,
  'inline-style': /<style\b|\bstyle\s*=/i,
  'inline-handler': /\bon[a-z]+\s*=/i,
  eval: /\beval\b|\bFunction\s*\(|\bset(?:Timeout|Interval)\b/,
};

const NEARBY = 2;

export function verifyClaim(lines: string[], claim: Claim): Verification {
  const text = normalize(claim.text);
  if (text.length < 3) return { verified: false, reason: 'citation is empty or too short' };

  const line = locate(lines, text, claim.text.split('\n').length, claim.line);
  if (line === undefined) return { verified: false, reason: `the cited text is not in the file (cited line ${claim.line})` };

  if (claim.kind === 'external-source') {
    if (!claim.source) return { verified: false, reason: 'external source without a source' };
    if (!isSelf(claim.source) && !sourceInText(claim.source, text)) {
      return { verified: false, reason: `the cited text does not contain ${claim.source}` };
    }
  } else if (!KIND_SHAPE[claim.kind]!.test(text)) {
    return { verified: false, reason: `the cited text does not look like ${claim.kind}` };
  }
  return { verified: true, line };
}

/** Line where `text` starts: the cited line first, then nearby, then anywhere in the file. */
function locate(lines: string[], text: string, span: number, cited: number): number | undefined {
  const matchesAt = (i: number) => i >= 1 && i <= lines.length && normalize(lines.slice(i - 1, i - 1 + span).join(' ')).includes(text);
  for (let d = 0; d <= NEARBY; d++) {
    if (matchesAt(cited - d)) return cited - d;
    if (d > 0 && matchesAt(cited + d)) return cited + d;
  }
  for (let i = 1; i <= lines.length; i++) if (matchesAt(i)) return i;
  return undefined;
}

const isSelf = (source: string) => /^'?self'?$/i.test(source.trim());

const PLACEHOLDER = /\$\{[^}]*\}|\{[^}]*\}|<[^>]*>/g;

/**
 * The source, or its literal pieces around runtime placeholders
 * (`wss://${API_HOST}/socket` → `wss://`, `/socket`), or its host.
 */
export function sourceInText(source: string, text: string): boolean {
  const s = source.toLowerCase().replace(/\/+$/, '');
  const t = text.toLowerCase();
  if (t.includes(s)) return true;
  const pieces = s.split(PLACEHOLDER).map((p) => p.trim()).filter((p) => p.length >= 3);
  if (pieces.length > 0 && s.match(PLACEHOLDER) && pieces.every((p) => t.includes(p))) return true;
  const host = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/.exec(s)?.[1];
  return host !== undefined && !host.match(PLACEHOLDER) && host.includes('.') && t.includes(host);
}

/**
 * The CSP form of a source: the origin of a URL, `self` for relative paths.
 * Sources with runtime placeholders are kept as written.
 */
export function normalizeSource(source: string): string {
  const s = source.trim();
  if (isSelf(s)) return 'self';
  if (s.startsWith('//')) return /^\/\/([^/?#]+)/.exec(s)?.[1] ?? s;
  if (/^\.{0,2}\//.test(s)) return 'self';
  if (s.match(PLACEHOLDER)) return s.replace(/\/+$/, '');
  try {
    const url = new URL(s);
    if (['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return url.origin;
  } catch {
    // not a URL: keep as written
  }
  return s;
}
