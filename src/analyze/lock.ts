import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parse, stringify } from 'yaml';
import type { FindingKind } from './candidates.js';

// csp.lock: a cache of the code analysis, written only by the tool and
// committed. It can be rebuilt entirely from the code. Sorted keys, so that
// the diff in a PR shows reviewers exactly what the LLM concluded.

export interface Evidence {
  line: number;
  text: string;
}

export interface LockFinding {
  kind: FindingKind;
  source?: string;
  directive?: string;
  evidence: Evidence;
  provenance?: string;
  dev_only?: boolean;
  verified: boolean;
  /** Why the citation check failed. */
  unverified_reason?: string;
  /** Found by a candidate pattern, but the LLM did not report it. */
  missed_by_llm?: boolean;
}

/** A candidate the LLM judged not relevant, kept with its reason so the lock diff shows it. */
export interface Dismissed {
  kind: FindingKind;
  value?: string;
  evidence: Evidence;
  reason: string;
}

export interface LockFile {
  hash: string;
  status: 'ok' | 'error';
  error?: string;
  findings: LockFinding[];
  dismissed: Dismissed[];
}

export interface Lock {
  version: 1;
  model: string;
  prompt_version: number;
  files: Record<string, LockFile>;
}

export const hashContent = (content: string) => `sha256:${createHash('sha256').update(content).digest('hex')}`;

export async function readLock(path: string): Promise<Lock | undefined> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw e;
  }
  const data = parse(text) as Lock | null;
  if (!data || data.version !== 1 || typeof data.files !== 'object') {
    throw new Error(`${path} is not a csp.lock written by this version of cspgen`);
  }
  return data;
}

export function serializeLock(lock: Lock): string {
  const files = Object.fromEntries(
    Object.entries(lock.files).map(([path, f]) => [
      path,
      {
        ...f,
        findings: [...f.findings].sort((a, b) => a.evidence.line - b.evidence.line || a.kind.localeCompare(b.kind)),
        dismissed: [...f.dismissed].sort((a, b) => a.evidence.line - b.evidence.line),
      },
    ]),
  );
  // Model and prompt version on top, then everything else with sorted keys.
  const header = stringify({ version: lock.version, model: lock.model, prompt_version: lock.prompt_version });
  const body = stringify({ files }, { sortMapEntries: true, lineWidth: 0 });
  return `# Written by cspgen analyze: what the LLM found in the code, checked against it. Do not edit by hand.\n${header}\n${body}`;
}
