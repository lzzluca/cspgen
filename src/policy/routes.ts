import type { Config } from '../config/schema.js';

// Route patterns in csp.yml: exact paths ("/"), named segments ("/products/:id")
// and a trailing or inner wildcard ("/admin/*").

export function routeMatches(pattern: string, path: string): boolean {
  const regex = pattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/:[A-Za-z_][A-Za-z0-9_]*/g, '[^/]+'))
    .join('.*');
  return new RegExp(`^${regex}/?$`).test(path);
}

/** The document serving a URL path. The most specific pattern (longest) wins. */
export function documentForPath(config: Config, path: string): string | undefined {
  let best: { name: string; length: number } | undefined;
  for (const [name, doc] of Object.entries(config.documents)) {
    for (const pattern of doc.routes) {
      if (routeMatches(pattern, path) && (!best || pattern.length > best.length)) {
        best = { name, length: pattern.length };
      }
    }
  }
  return best?.name;
}
