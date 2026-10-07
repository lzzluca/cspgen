import { findCandidates, type Candidate } from './candidates.js';
import type { SelectedFile } from './files.js';
import { LlmError, parseJsonAnswer, type LlmClient } from './llm.js';
import { hashContent, type Dismissed, type Lock, type LockFile, type LockFinding } from './lock.js';
import {
  ANSWER_JSON_SCHEMA,
  AnswerSchema,
  PROMPT_VERSION,
  buildMessages,
  retryMessages,
  windowsOf,
  type Answer,
} from './prompt.js';
import { normalizeSource, verifyClaim } from './verify.js';

// `cspgen analyze`: asks the LLM about each changed file, checks every answer
// against the code, and records the result in csp.lock. The LLM proposes;
// what fails a check stays in the lock, marked, and never disappears.

export type Progress =
  | { type: 'start'; path: string; index: number; total: number }
  | { type: 'done'; path: string; file: LockFile };

export interface AnalyzeResult {
  lock: Lock;
  analyzed: string[];
  reused: string[];
  /** Why cached answers could not be reused at all (model or prompt changed). */
  invalidated?: string;
}

export function isReusable(previous: Lock | undefined, model: string, path: string, hash: string): boolean {
  if (!previous || invalidation(previous, model)) return false;
  const f = previous.files[path];
  return f !== undefined && f.hash === hash && f.status === 'ok';
}

/** Why none of the cached answers can be reused. */
export function invalidation(previous: Lock, model: string): string | undefined {
  if (previous.model !== model) return `model changed from ${previous.model} to ${model}`;
  if (previous.prompt_version !== PROMPT_VERSION) return `prompt version changed to ${PROMPT_VERSION}`;
  return undefined;
}

export interface Staleness {
  /** Set when the whole lock is out of date (no lock, other model or prompt). */
  reason?: string;
  changed: string[];
  added: string[];
  removed: string[];
  errors: string[];
}

/** What `cspgen analyze` would do, without asking the LLM: used by `check` in CI. */
export function staleness(files: SelectedFile[], lock: Lock | undefined, model: string): Staleness {
  const result: Staleness = { changed: [], added: [], removed: [], errors: [] };
  if (!lock) return { ...result, reason: 'there is no csp.lock yet' };
  result.reason = invalidation(lock, model);
  const current = new Set(files.map((f) => f.path));
  for (const f of files) {
    const cached = lock.files[f.path];
    if (!cached) result.added.push(f.path);
    else if (cached.hash !== hashContent(f.content)) result.changed.push(f.path);
    else if (cached.status === 'error') result.errors.push(f.path);
  }
  result.removed = Object.keys(lock.files).filter((p) => !current.has(p));
  return result;
}

export const isStale = (s: Staleness) =>
  s.reason !== undefined || s.changed.length + s.added.length + s.removed.length + s.errors.length > 0;

export async function analyze(
  files: SelectedFile[],
  client: LlmClient,
  previous: Lock | undefined,
  onProgress: (p: Progress) => void = () => {},
): Promise<AnalyzeResult> {
  const lock: Lock = { version: 1, model: client.model, prompt_version: PROMPT_VERSION, files: {} };
  const analyzed: string[] = [];
  const reused: string[] = [];
  const invalidated = previous ? invalidation(previous, client.model) : undefined;

  const todo = files.filter((f) => {
    const hash = hashContent(f.content);
    if (isReusable(previous, client.model, f.path, hash)) {
      lock.files[f.path] = previous!.files[f.path]!;
      reused.push(f.path);
      return false;
    }
    return true;
  });

  for (const [i, f] of todo.entries()) {
    onProgress({ type: 'start', path: f.path, index: i + 1, total: todo.length });
    const result = await analyzeFile(f, client);
    lock.files[f.path] = result;
    analyzed.push(f.path);
    onProgress({ type: 'done', path: f.path, file: result });
  }
  return { lock, analyzed, reused, invalidated };
}

export async function analyzeFile(file: SelectedFile, client: LlmClient): Promise<LockFile> {
  const hash = hashContent(file.content);
  const lines = file.content.split('\n');
  const candidates = findCandidates(file.content);

  const answers: Answer[] = [];
  for (const w of windowsOf(file.content, candidates)) {
    try {
      answers.push(await ask(client, buildMessages(file.path, lines.length, w)));
    } catch (e) {
      if (e instanceof AnswerError || e instanceof LlmError) {
        return { hash, status: 'error', error: e.message, findings: [], dismissed: [] };
      }
      throw e;
    }
  }
  return { hash, status: 'ok', ...checkAnswers(lines, candidates, answers) };
}

class AnswerError extends Error {}

/** One question, validated; an invalid answer is retried once with the error. */
async function ask(client: LlmClient, messages: Parameters<LlmClient['complete']>[0]): Promise<Answer> {
  const first = await client.complete(messages, ANSWER_JSON_SCHEMA);
  const parsed = parseAnswer(first);
  if (parsed.ok) return parsed.answer;
  const second = await client.complete(retryMessages(messages, first, parsed.error), ANSWER_JSON_SCHEMA);
  const retried = parseAnswer(second);
  if (retried.ok) return retried.answer;
  throw new AnswerError(`invalid answer after one retry: ${retried.error}`);
}

function parseAnswer(text: string): { ok: true; answer: Answer } | { ok: false; error: string } {
  let json: unknown;
  try {
    json = parseJsonAnswer(text);
  } catch {
    return { ok: false, error: 'it is not valid JSON' };
  }
  const result = AnswerSchema.safeParse(json);
  if (!result.success) {
    const issues = result.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
    return { ok: false, error: issues.join('; ') };
  }
  return { ok: true, answer: result.data };
}

/** Citation checks on every finding, then the cross-check against the candidates. */
export function checkAnswers(
  lines: string[],
  candidates: Candidate[],
  answers: Answer[],
): { findings: LockFinding[]; dismissed: Dismissed[] } {
  const findings: LockFinding[] = [];
  const seen = new Set<string>();

  for (const f of answers.flatMap((a) => a.findings)) {
    const check = verifyClaim(lines, f);
    const line = check.verified ? check.line : f.line;
    const source = f.kind === 'external-source' && f.source ? normalizeSource(f.source) : undefined;
    // Overlapping windows can report the same thing twice.
    const key = `${f.kind}|${source ?? ''}|${line}|${check.verified}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      kind: f.kind,
      ...(source !== undefined ? { source } : {}),
      directive: f.directive,
      evidence: { line, text: check.verified ? lines[line - 1]!.trim() : f.text.trim() },
      ...(f.provenance ? { provenance: f.provenance } : {}),
      ...(f.dev_only ? { dev_only: true } : {}),
      verified: check.verified,
      ...(check.verified ? {} : { unverified_reason: check.reason }),
    });
  }

  // Verdicts by candidate id: across windows, "relevant" wins over "not relevant".
  const verdicts = new Map<string, { relevant: boolean; reason: string }>();
  for (const v of answers.flatMap((a) => a.candidates)) {
    const earlier = verdicts.get(v.id);
    if (!earlier || (!earlier.relevant && v.relevant)) verdicts.set(v.id, v);
  }

  const dismissed: Dismissed[] = [];
  for (const c of candidates) {
    const verdict = verdicts.get(c.id);
    if (verdict && !verdict.relevant) {
      dismissed.push({ kind: c.kind, ...(c.value ? { value: c.value } : {}), evidence: { line: c.line, text: c.text }, reason: verdict.reason });
      continue;
    }
    if (findings.some((f) => f.verified && covers(f, c))) continue;
    // Relevant but not reported, or no verdict at all: keep it, marked.
    findings.push({
      kind: c.kind,
      ...(c.value ? { source: normalizeSource(c.value) } : {}),
      ...(c.directive ? { directive: c.directive } : {}),
      evidence: { line: c.line, text: c.text },
      verified: true,
      missed_by_llm: true,
    });
  }
  return { findings, dismissed };
}

function covers(f: LockFinding, c: Candidate): boolean {
  if (f.kind !== c.kind || Math.abs(f.evidence.line - c.line) > 2) return false;
  if (c.kind !== 'external-source' || !c.value || !f.source) return true;
  const expected = normalizeSource(c.value);
  return f.source === expected || f.source.includes(expected) || expected.includes(f.source);
}
