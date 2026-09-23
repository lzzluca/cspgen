// Source expressions: the values that appear inside a CSP directive.
// In csp.yml keywords may be written with or without single quotes
// (`self` or `'self'`); here they are normalized to the header form.

export const KEYWORDS = [
  'self',
  'none',
  'unsafe-inline',
  'unsafe-eval',
  'unsafe-hashes',
  'strict-dynamic',
  'report-sample',
  'wasm-unsafe-eval',
] as const;

export type Keyword = (typeof KEYWORDS)[number];

/** Placeholder the tool emits for per-request nonces; the stack snippet fills it. */
export const NONCE_PLACEHOLDER = "'nonce-{NONCE}'";

export type SourceValue =
  | { kind: 'keyword'; keyword: Keyword; text: string }
  | { kind: 'nonce'; text: string }
  | { kind: 'hash'; text: string }
  | { kind: 'wildcard'; text: '*' }
  | { kind: 'scheme'; scheme: string; text: string }
  | { kind: 'host'; host: string; text: string }
  | { kind: 'token'; text: string };

/**
 * Directives whose values are not source expressions (sandbox flags,
 * reporting endpoints, trusted-types policy names). Their values are kept verbatim.
 */
export const TOKEN_DIRECTIVES = new Set([
  'sandbox',
  'report-uri',
  'report-to',
  'trusted-types',
  'require-trusted-types-for',
]);

export class InvalidValueError extends Error {}

function isKeyword(value: string): value is Keyword {
  return (KEYWORDS as readonly string[]).includes(value);
}

export function parseSourceValue(raw: string, directive: string): SourceValue {
  const trimmed = raw.trim();
  if (TOKEN_DIRECTIVES.has(directive)) return { kind: 'token', text: trimmed };

  const quoted = trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'");
  const inner = quoted ? trimmed.slice(1, -1) : trimmed;

  if (isKeyword(inner)) return { kind: 'keyword', keyword: inner, text: `'${inner}'` };
  if (inner === 'nonce') return { kind: 'nonce', text: NONCE_PLACEHOLDER };
  if (/^nonce-[A-Za-z0-9+/_=-]+$/.test(inner)) return { kind: 'nonce', text: `'${inner}'` };
  if (/^sha(256|384|512)-[A-Za-z0-9+/_=-]+$/.test(inner)) return { kind: 'hash', text: `'${inner}'` };

  if (quoted) throw new InvalidValueError(`unknown CSP keyword ${trimmed}`);
  if (/\s/.test(inner)) throw new InvalidValueError(`value "${raw}" contains whitespace`);

  if (inner === '*') return { kind: 'wildcard', text: '*' };
  if (/^[a-z][a-z0-9+.-]*:$/i.test(inner)) {
    return { kind: 'scheme', scheme: inner.slice(0, -1).toLowerCase(), text: inner.toLowerCase() };
  }
  return { kind: 'host', host: hostOf(inner), text: inner };
}

/** Extracts the bare host name from a host-source like `wss://api.example.com:443/path`. */
export function hostOf(hostSource: string): string {
  const withoutScheme = hostSource.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const hostPort = withoutScheme.split('/')[0] ?? '';
  return hostPort.replace(/:(\d+|\*)$/, '').toLowerCase();
}

const DEV_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '[::1]']);

/** True for sources that only make sense on a developer machine. */
export function isDevSource(value: SourceValue): boolean {
  if (value.kind !== 'host') return false;
  return DEV_HOSTS.has(value.host) || value.host.endsWith('.localhost');
}
