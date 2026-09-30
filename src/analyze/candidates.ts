// Candidates: what a few regexes find for sure (literal URLs, tags, inline
// handlers, eval). They are not meant to be complete: finding what they cannot
// see (URLs built at runtime) is the LLM's job. They are a safety net: the LLM
// must give a verdict on each one, and one it ignores is kept anyway.

export const FINDING_KINDS = ['external-source', 'inline-script', 'inline-style', 'inline-handler', 'eval'] as const;
export type FindingKind = (typeof FINDING_KINDS)[number];

export interface Candidate {
  id: string;
  line: number;
  kind: FindingKind;
  /** The URL or path, for external sources. */
  value?: string;
  /** The line, trimmed (and cut around the match when long). */
  text: string;
  /** Directive when the context makes it obvious (`<script src>` → script-src). */
  directive?: string;
}

interface Pattern {
  re: RegExp;
  classify: (match: RegExpExecArray) => Omit<Candidate, 'id' | 'line' | 'text'> | undefined;
}

const attr = (tag: string, name: string) => new RegExp(`\\s${name}\\s*=\\s*["']?([^"'\\s>]+)`, 'i').exec(tag)?.[1];

/** URLs that name things instead of loading them. */
const NOT_LOADED = /^https?:\/\/(www\.)?w3\.org\//i;

const PATTERNS: Pattern[] = [
  {
    re: /\b(?:https?|wss?):\/\/[A-Za-z0-9.-]+(?::\d+)?[^\s'"`<>)\]},;]*/g,
    classify: (m) => (NOT_LOADED.test(m[0]) ? undefined : { kind: 'external-source', value: m[0] }),
  },
  {
    re: /<script\b[^>]*>?/gi,
    classify: (m) => {
      const src = attr(m[0], 'src');
      return src ? { kind: 'external-source', value: src, directive: 'script-src' } : { kind: 'inline-script', directive: 'script-src' };
    },
  },
  {
    re: /<link\b[^>]*>?/gi,
    classify: (m) => {
      const href = attr(m[0], 'href');
      const rel = attr(m[0], 'rel')?.toLowerCase();
      if (!href) return undefined;
      return { kind: 'external-source', value: href, directive: rel === 'stylesheet' ? 'style-src' : undefined };
    },
  },
  {
    re: /<iframe\b[^>]*>?/gi,
    classify: (m) => {
      const src = attr(m[0], 'src');
      return src ? { kind: 'external-source', value: src, directive: 'frame-src' } : undefined;
    },
  },
  {
    // Connections and workers: the URL is often relative or built at runtime, so the regex keeps the call.
    re: /\b(fetch|new\s+WebSocket|new\s+EventSource|navigator\.sendBeacon|new\s+(?:Shared)?Worker|importScripts)\s*\(\s*(?:[`'"]([^`'"]*))?/g,
    classify: (m) => ({
      kind: 'external-source',
      ...(m[2] ? { value: m[2] } : {}),
      directive: /Worker|importScripts/.test(m[1]!) ? 'worker-src' : 'connect-src',
    }),
  },
  { re: /<style\b/gi, classify: () => ({ kind: 'inline-style', directive: 'style-src' }) },
  // Only quoted values: JSX `style={...}` and `onClick={...}` go through the DOM API, which CSP does not block.
  { re: /\sstyle\s*=\s*["']/gi, classify: () => ({ kind: 'inline-style', directive: 'style-src' }) },
  { re: /\son[a-z]{3,}\s*=\s*["']/gi, classify: () => ({ kind: 'inline-handler', directive: 'script-src' }) },
  {
    re: /\beval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]/g,
    classify: () => ({ kind: 'eval', directive: 'script-src' }),
  },
];

const MAX_TEXT = 200;

export function findCandidates(content: string): Candidate[] {
  const lineStarts = [0];
  for (let i = 0; i < content.length; i++) if (content[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (index: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const lineText = (line: number, index: number) => {
    const start = lineStarts[line - 1]!;
    const end = line < lineStarts.length ? lineStarts[line]! - 1 : content.length;
    const raw = content.slice(start, end).replace(/\r$/, '');
    if (raw.trim().length <= MAX_TEXT) return raw.trim();
    const at = Math.max(0, index - start - MAX_TEXT / 2);
    return raw.slice(at, at + MAX_TEXT).trim();
  };

  const found: Candidate[] = [];
  const seen = new Set<string>();
  for (const { re, classify } of PATTERNS) {
    re.lastIndex = 0;
    for (let m = re.exec(content); m !== null; m = re.exec(content)) {
      const c = classify(m);
      if (!c) continue;
      const line = lineOf(m.index);
      // A URL inside `<script src>` is found twice: keep the one that knows the directive.
      const key = `${line}|${c.kind}|${c.value ?? ''}`;
      if (seen.has(key)) {
        if (c.directive) {
          const earlier = found.find((f) => `${f.line}|${f.kind}|${f.value ?? ''}` === key);
          if (earlier) earlier.directive ??= c.directive;
        }
        continue;
      }
      seen.add(key);
      found.push({ id: '', line, text: lineText(line, m.index), ...c });
    }
  }
  found.sort((a, b) => a.line - b.line);
  found.forEach((c, i) => (c.id = `c${i + 1}`));
  return found;
}
