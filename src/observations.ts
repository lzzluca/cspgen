import { readFile } from 'node:fs/promises';
import { parse, stringify } from 'yaml';
import type { Proposal } from './reports/import.js';

// csp.observations.yml: what browsers actually did, as opposed to what the code suggests.
// Written only by the tool. Kept apart from csp.lock because it cannot be rebuilt from the code.

export type ObservationOrigin = 'production-report' | 'playwright' | 'manual';

export interface Observation {
  document: string;
  directive: string;
  source: string;
  count: number;
  examples: string[];
  from: ObservationOrigin;
  env?: string;
  last_seen: string;
}

export interface ObservationsFile {
  version: 1;
  observations: Observation[];
}

export async function readObservations(path: string): Promise<ObservationsFile> {
  try {
    const data = parse(await readFile(path, 'utf8')) as ObservationsFile | null;
    return data && Array.isArray(data.observations) ? data : { version: 1, observations: [] };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, observations: [] };
    throw e;
  }
}

/** Adds imported proposals, summing counts of observations already recorded. */
export function mergeObservations(
  file: ObservationsFile,
  proposals: Proposal[],
  from: ObservationOrigin,
  seenAt: Date,
): ObservationsFile {
  const key = (o: { document: string; directive: string; source: string; from: string; env?: string }) =>
    `${o.document}|${o.directive}|${o.source}|${o.from}|${o.env ?? ''}`;
  const byKey = new Map(file.observations.map((o) => [key(o), { ...o, examples: [...o.examples] }]));

  for (const p of proposals) {
    const k = key({ ...p, from });
    const existing = byKey.get(k);
    if (existing) {
      existing.count += p.count;
      existing.examples = [...new Set([...existing.examples, ...p.examples])].slice(0, 3);
      existing.last_seen = seenAt.toISOString();
    } else {
      byKey.set(k, {
        document: p.document,
        directive: p.directive,
        source: p.source,
        count: p.count,
        examples: p.examples,
        from,
        last_seen: seenAt.toISOString(),
      });
    }
  }

  const observations = [...byKey.values()].sort(
    (a, b) => a.document.localeCompare(b.document) || a.directive.localeCompare(b.directive) || b.count - a.count,
  );
  return { version: 1, observations };
}

export function serializeObservations(file: ObservationsFile): string {
  return `# Written by cspgen: CSP violations actually seen by browsers. Do not edit by hand.\n${stringify(file, { lineWidth: 0 })}`;
}
