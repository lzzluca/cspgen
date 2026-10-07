import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { analyze, analyzeFile, checkAnswers, isStale, staleness } from '../src/analyze/analyze.js';
import { findCandidates } from '../src/analyze/candidates.js';
import { globToRegExp, isExcludedPath, selectFiles, shouldAnalyze } from '../src/analyze/files.js';
import type { ChatMessage, LlmClient } from '../src/analyze/llm.js';
import { hashContent, serializeLock } from '../src/analyze/lock.js';
import { PROMPT_VERSION, WINDOW_LINES, windowsOf, type Answer, type AnswerFinding } from '../src/analyze/prompt.js';
import { normalizeSource, sourceInText, verifyClaim } from '../src/analyze/verify.js';

/** A fake LLM: answers in order, and records what it was asked. */
function fakeClient(...answers: (string | object)[]): LlmClient & { calls: ChatMessage[][] } {
  const calls: ChatMessage[][] = [];
  return {
    model: 'fake-model',
    calls,
    async complete(messages) {
      calls.push(messages);
      const next = answers.shift();
      if (next === undefined) throw new Error('unexpected LLM call');
      return typeof next === 'string' ? next : JSON.stringify(next);
    },
  };
}

const INDEX_HTML = `<!doctype html>
<html>
  <head>
    <script type="module" src="/src/main.tsx"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
  </head>
  <body onload="init()">
    <svg xmlns="http://www.w3.org/2000/svg"></svg>
  </body>
</html>`;

const finding = (f: Partial<AnswerFinding> & Pick<AnswerFinding, 'kind' | 'line' | 'text'>): AnswerFinding => ({
  source: '',
  directive: 'script-src',
  ...f,
});

describe('candidates', () => {
  it('finds literal URLs, tags and inline handlers, and knows the obvious directives', () => {
    const found = findCandidates(INDEX_HTML);
    expect(found.map((c) => [c.id, c.line, c.kind, c.value, c.directive])).toEqual([
      ['c1', 4, 'external-source', '/src/main.tsx', 'script-src'],
      ['c2', 5, 'external-source', 'https://fonts.googleapis.com/css2?family=Inter', 'style-src'],
      ['c3', 7, 'inline-handler', undefined, 'script-src'],
    ]);
  });

  it('ignores JSX props, which CSP does not block, and XML namespaces', () => {
    const jsx = `<div style={{ color: 'red' }} onClick={() => go()} />\n<svg xmlns="http://www.w3.org/2000/svg" />`;
    expect(findCandidates(jsx)).toEqual([]);
  });

  it('finds connections and workers, with relative or runtime URLs', () => {
    const code = 'res = await fetch(`/api${path}`, init);\nconst ws = new WebSocket(url);\nnew Worker("/worker.js")\nfetch("https://api.example.com/x")';
    expect(findCandidates(code).map((c) => [c.line, c.value, c.directive])).toEqual([
      [1, '/api${path}', 'connect-src'],
      [2, undefined, 'connect-src'],
      [3, '/worker.js', 'worker-src'],
      [4, 'https://api.example.com/x', 'connect-src'],
    ]);
    expect(normalizeSource('/api${path}')).toBe('self');
  });

  it('finds inline scripts, style attributes and eval', () => {
    const kinds = findCandidates(`<script>window.x = 1</script>\n<p style="color: red">\neval(code)\nsetTimeout("run()", 10)`).map((c) => c.kind);
    expect(kinds).toEqual(['inline-script', 'inline-style', 'eval', 'eval']);
  });
});

describe('verifyClaim', () => {
  const lines = INDEX_HTML.split('\n');

  it('verifies a citation that is on the cited line and contains the source', () => {
    expect(
      verifyClaim(lines, { kind: 'external-source', source: 'https://fonts.googleapis.com', line: 5, text: 'href="https://fonts.googleapis.com/css2?family=Inter"' }),
    ).toEqual({ verified: true, line: 5 });
  });

  it('corrects a line number that is off, nearby or anywhere in the file', () => {
    const claim = { kind: 'inline-handler' as const, text: '<body onload="init()">' };
    expect(verifyClaim(lines, { ...claim, line: 8 })).toEqual({ verified: true, line: 7 });
    expect(verifyClaim(lines, { ...claim, line: 1 })).toEqual({ verified: true, line: 7 });
  });

  it('tolerates different whitespace', () => {
    expect(verifyClaim(lines, { kind: 'inline-handler', line: 7, text: '<body   onload="init()" >'.replace(' >', '>') })).toEqual({ verified: true, line: 7 });
  });

  it('rejects text that is not in the file', () => {
    const check = verifyClaim(lines, { kind: 'external-source', source: 'https://cdn.tiny.cloud', line: 4, text: '<script src="https://cdn.tiny.cloud/tinymce.js">' });
    expect(check).toEqual({ verified: false, reason: 'the cited text is not in the file (cited line 4)' });
  });

  it('rejects a real line that does not contain the claimed source', () => {
    const check = verifyClaim(lines, { kind: 'external-source', source: 'https://cdn.tiny.cloud', line: 4, text: '<script type="module" src="/src/main.tsx"></script>' });
    expect(check).toEqual({ verified: false, reason: 'the cited text does not contain https://cdn.tiny.cloud' });
  });

  it('rejects a real line that does not look like the claimed kind', () => {
    const check = verifyClaim(lines, { kind: 'inline-script', line: 3, text: '<head>' });
    expect(check.verified).toBe(false);
  });

  it('rejects empty citations', () => {
    expect(verifyClaim(lines, { kind: 'eval', line: 1, text: ' ' }).verified).toBe(false);
  });
});

describe('sources', () => {
  it('matches runtime-built URLs by their literal pieces', () => {
    expect(sourceInText('wss://${API_HOST}/socket', 'new WebSocket(`wss://${host}/socket`)')).toBe(true);
    expect(sourceInText('wss://${API_HOST}/live', 'new WebSocket(`wss://${host}/socket`)')).toBe(false);
  });

  it('matches a source by its host', () => {
    expect(sourceInText('https://api.example.com', 'const host = "api.example.com"')).toBe(true);
  });

  it('normalizes to the CSP form', () => {
    expect(normalizeSource('https://api.deepseek.com/v1')).toBe('https://api.deepseek.com');
    expect(normalizeSource('http://localhost:4000/api')).toBe('http://localhost:4000');
    expect(normalizeSource('/src/main.tsx')).toBe('self');
    expect(normalizeSource("'self'")).toBe('self');
    expect(normalizeSource('//cdn.example.com/a.js')).toBe('cdn.example.com');
    expect(normalizeSource('wss://${API_HOST}/')).toBe('wss://${API_HOST}');
  });
});

describe('checkAnswers', () => {
  const lines = INDEX_HTML.split('\n');
  const candidates = findCandidates(INDEX_HTML);

  it('keeps verified findings, marks unverified ones, and records dismissed candidates', () => {
    const answer: Answer = {
      findings: [
        finding({ kind: 'external-source', source: '/src/main.tsx', line: 4, text: 'src="/src/main.tsx"', provenance: 'app bundle' }),
        finding({ kind: 'external-source', source: 'https://cdn.tiny.cloud', directive: 'script-src', line: 6, text: '<script src="https://cdn.tiny.cloud">' }),
        finding({ kind: 'inline-handler', line: 7, text: '<body onload="init()">' }),
      ],
      candidates: [
        { id: 'c1', relevant: true, reason: 'app bundle' },
        { id: 'c2', relevant: false, reason: 'test only' },
        { id: 'c3', relevant: true, reason: 'inline handler' },
      ],
    };
    const { findings, dismissed } = checkAnswers(lines, candidates, [answer]);
    expect(findings).toEqual([
      { kind: 'external-source', source: 'self', directive: 'script-src', evidence: { line: 4, text: '<script type="module" src="/src/main.tsx"></script>' }, provenance: 'app bundle', verified: true },
      {
        kind: 'external-source',
        source: 'https://cdn.tiny.cloud',
        directive: 'script-src',
        evidence: { line: 6, text: '<script src="https://cdn.tiny.cloud">' },
        verified: false,
        unverified_reason: 'the cited text is not in the file (cited line 6)',
      },
      { kind: 'inline-handler', directive: 'script-src', evidence: { line: 7, text: '<body onload="init()">' }, verified: true },
    ]);
    expect(dismissed).toEqual([
      { kind: 'external-source', value: 'https://fonts.googleapis.com/css2?family=Inter', evidence: { line: 5, text: candidates[1]!.text }, reason: 'test only' },
    ]);
  });

  it('keeps candidates the LLM ignored, or judged relevant without reporting, as missed_by_llm', () => {
    const answer: Answer = { findings: [], candidates: [{ id: 'c1', relevant: true, reason: 'bundle' }] };
    const { findings } = checkAnswers(lines, candidates, [answer]);
    expect(findings.map((f) => [f.evidence.line, f.kind, f.source, f.directive, f.missed_by_llm])).toEqual([
      [4, 'external-source', 'self', 'script-src', true],
      [5, 'external-source', 'https://fonts.googleapis.com', 'style-src', true],
      [7, 'inline-handler', undefined, 'script-src', true],
    ]);
  });

  it('does not count an unverified finding as covering a candidate', () => {
    const answer: Answer = {
      findings: [finding({ kind: 'inline-handler', line: 7, text: '<body onclick="x()">' })],
      candidates: [
        { id: 'c1', relevant: false, reason: 'x' },
        { id: 'c2', relevant: false, reason: 'x' },
      ],
    };
    const { findings } = checkAnswers(lines, candidates, [answer]);
    expect(findings.map((f) => [f.verified, f.missed_by_llm ?? false])).toEqual([
      [false, false],
      [true, true],
    ]);
  });
});

describe('analyzeFile', () => {
  const file = { path: 'index.html', content: INDEX_HTML };
  const empty = { findings: [], candidates: [] };

  it('sends numbered lines and the candidates', async () => {
    const client = fakeClient(empty);
    await analyzeFile(file, client);
    const user = client.calls[0]![1]!.content;
    expect(user).toContain('File: index.html\n');
    expect(user).toContain(' 4|     <script type="module" src="/src/main.tsx"></script>');
    expect(user).toContain('- c3 (line 7, inline-handler): <body onload="init()">');
  });

  it('retries an invalid answer once, with the error', async () => {
    const client = fakeClient('not json', '```json\n{"findings": [], "candidates": []}\n```');
    const result = await analyzeFile(file, client);
    expect(result.status).toBe('ok');
    expect(client.calls[1]!.at(-1)!.content).toContain('That answer is invalid: it is not valid JSON');
  });

  it('marks the file as error after a second invalid answer', async () => {
    const client = fakeClient({ findings: [{ kind: 'nope' }] }, { findings: 'x' });
    const result = await analyzeFile(file, client);
    expect(result).toMatchObject({ status: 'error', findings: [], dismissed: [] });
    expect(result.error).toMatch(/^invalid answer after one retry: findings/);
  });

  it('splits long files into overlapping windows', async () => {
    const content = Array.from({ length: 600 }, (_, i) => (i === 299 ? 'fetch("https://api.example.com/x")' : `line ${i + 1}`)).join('\n');
    const windows = windowsOf(content, findCandidates(content));
    expect(windows.map((w) => [w.start, w.end, w.candidates.length])).toEqual([
      [1, 300, 1],
      [281, 580, 1],
      [561, 600, 0],
    ]);
    const hit = finding({ kind: 'external-source', source: 'https://api.example.com', directive: 'connect-src', line: 300, text: 'fetch("https://api.example.com/x")' });
    const client = fakeClient(
      { findings: [hit], candidates: [{ id: 'c1', relevant: true, reason: 'api' }] },
      { findings: [hit], candidates: [{ id: 'c1', relevant: true, reason: 'api' }] },
      empty,
    );
    const result = await analyzeFile({ path: 'big.js', content }, client);
    expect(client.calls).toHaveLength(3);
    expect(client.calls[1]![1]!.content).toContain('(lines 281-580 of 600)');
    expect(result.findings).toHaveLength(1);
    expect(WINDOW_LINES).toBe(300);
  });
});

describe('analyze and csp.lock', () => {
  const a = { path: 'a.js', content: 'fetch("/api")' };
  const b = { path: 'b.js', content: 'export const x = 1' };
  const empty = { findings: [], candidates: [] };

  it('asks only about files whose hash changed', async () => {
    const first = await analyze([a, b], fakeClient(empty, empty), undefined);
    expect(first.analyzed).toEqual(['a.js', 'b.js']);

    const changed = { ...b, content: 'export const x = 2' };
    const client = fakeClient(empty);
    const second = await analyze([a, changed], client, first.lock);
    expect(second.reused).toEqual(['a.js']);
    expect(second.analyzed).toEqual(['b.js']);
    expect(second.lock.files['b.js']!.hash).toBe(hashContent('export const x = 2'));
  });

  it('asks again about every file when the model changes, and about files in error', async () => {
    const first = await analyze([a], fakeClient(empty), undefined);
    const other = { ...fakeClient(empty), model: 'other-model' };
    const second = await analyze([a], other, first.lock);
    expect(second.invalidated).toBe('model changed from fake-model to other-model');
    expect(second.analyzed).toEqual(['a.js']);

    const broken = await analyze([a], fakeClient('x', 'y'), undefined);
    expect((await analyze([a], fakeClient(empty), broken.lock)).analyzed).toEqual(['a.js']);
  });

  it('drops files that are no longer selected', async () => {
    const first = await analyze([a, b], fakeClient(empty, empty), undefined);
    const second = await analyze([a], fakeClient(), first.lock);
    expect(Object.keys(second.lock.files)).toEqual(['a.js']);
  });

  it('serializes with the model on top and sorted keys', async () => {
    const { lock } = await analyze([b, a], fakeClient(empty, empty), undefined);
    const text = serializeLock(lock);
    expect(text.split('\n').slice(1, 4)).toEqual(['version: 1', 'model: fake-model', `prompt_version: ${PROMPT_VERSION}`]);
    expect(Object.keys((parse(text) as { files: object }).files)).toEqual(['a.js', 'b.js']);
  });
});

describe('staleness (check in CI)', () => {
  const a = { path: 'a.js', content: 'fetch("/api")' };
  const b = { path: 'b.js', content: 'export const x = 1' };
  const empty = { findings: [], candidates: [] };

  it('is up to date right after an analysis', async () => {
    const { lock } = await analyze([a, b], fakeClient(empty, empty), undefined);
    expect(isStale(staleness([a, b], lock, 'fake-model'))).toBe(false);
  });

  it('lists changed, new, removed and failed files', async () => {
    const { lock } = await analyze([a, b], fakeClient(empty, 'x', 'y'), undefined);
    const c = { path: 'c.js', content: 'x' };
    expect(staleness([{ ...a, content: 'fetch("/v2")' }, c], lock, 'fake-model')).toEqual({
      reason: undefined,
      changed: ['a.js'],
      added: ['c.js'],
      removed: ['b.js'],
      errors: [],
    });
    expect(staleness([a, b], lock, 'fake-model').errors).toEqual(['b.js']);
  });

  it('is stale without a lock, or with another model', async () => {
    expect(staleness([a], undefined, 'fake-model').reason).toBe('there is no csp.lock yet');
    const { lock } = await analyze([a], fakeClient(empty), undefined);
    const other = staleness([a], lock, 'other-model');
    expect(other.reason).toBe('model changed from fake-model to other-model');
    expect(isStale(other)).toBe(true);
  });
});

describe('file selection', () => {
  it('excludes dependencies, lockfiles, docs and cspgen files', () => {
    for (const p of ['node_modules/x/index.js', 'apps/web/dist/app.js', 'pnpm-lock.yaml', 'README.md', 'csp.yml', 'deps/phoenix/priv/x.js', 'logo.png']) {
      expect(isExcludedPath(p), p).toBe(true);
    }
    for (const p of ['apps/web/index.html', 'lib/app_web/router.ex', 'apps/api/.env.example']) {
      expect(isExcludedPath(p), p).toBe(false);
    }
  });

  it('applies analysis.exclude globs', () => {
    expect(isExcludedPath('docs/guide/setup.html', ['docs/**'])).toBe(true);
    expect(isExcludedPath('apps/web/src/x.test.ts', ['*.test.ts'])).toBe(true);
    expect(isExcludedPath('apps/web/src/x.ts', ['*.test.ts'])).toBe(false);
    expect(globToRegExp('src/**/*.js').test('src/a/b/c.js')).toBe(true);
    expect(globToRegExp('src/**/*.js').test('src/c.js')).toBe(true);
  });

  it('sends frontend files always, other files only with a candidate', () => {
    expect(shouldAnalyze('src/utils.ts', 'export const x = 1')).toBe(true);
    expect(shouldAnalyze('lib/app.ex', 'defmodule App do end')).toBe(false);
    expect(shouldAnalyze('config/config.exs', 'config :app, url: "https://cdn.example.com"')).toBe(true);
  });

  it('never sends untracked files such as .env', async () => {
    const root = mkdtempSync(join(tmpdir(), 'cspgen-'));
    const git = (...args: string[]) => execFileSync('git', args, { cwd: root, stdio: 'ignore' });
    git('init', '-q');
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, '.gitignore'), '.env\n');
    writeFileSync(join(root, '.env'), 'LLM_BASE_URL=https://api.deepseek.com\nLLM_API_KEY=secret\n');
    writeFileSync(join(root, 'src/app.js'), 'fetch("/api")\n');
    writeFileSync(join(root, 'notes.ex'), 'x = 1\n');
    git('add', '.gitignore', 'src/app.js', 'notes.ex');
    const selected = await selectFiles(root, [], async (p) => readFileSync(join(root, p), 'utf8'));
    expect(selected.map((f) => f.path)).toEqual(['src/app.js']);
  });
});
