import { readFileSync } from 'node:fs';
import { diffLines } from 'diff';
import { describe, expect, it } from 'vitest';
import { canonicalValue, ConfigEditor, EditError } from '../src/config/edit.js';
import { parseConfig } from '../src/config/load.js';
import { resolvePolicy } from '../src/policy/policy.js';
import { evaluate, isAccepted } from '../src/rules/evaluate.js';

const example = readFileSync(new URL('../examples/phoenix/csp.yml', import.meta.url), 'utf8');

/** Lines added/removed by an edit, ignoring unchanged ones. */
function changedLines(before: string, after: string) {
  const lines = (added: boolean) =>
    diffLines(before, after)
      .filter((c) => (added ? c.added : c.removed))
      .flatMap((c) => c.value.split('\n').filter(Boolean));
  return { removed: lines(false), added: lines(true) };
}

describe('ConfigEditor', () => {
  it('round-trips an untouched file byte for byte', () => {
    expect(new ConfigEditor(example).result()).toEqual({ text: example, changed: false });
  });

  it('finds a source whether written with or without quotes', () => {
    const editor = new ConfigEditor(example);
    expect(editor.find("'unsafe-inline'")).toEqual([
      { scope: { kind: 'document', name: 'learning' }, directive: 'script-src', index: 1 },
    ]);
    expect(editor.find('self', { scope: { kind: 'common' } }).map((l) => l.directive)).toEqual(['img-src', 'style-src', 'font-src']);
  });

  it('accepts a pending source by replacing the status with a reason', () => {
    const editor = new ConfigEditor(example);
    editor.accept(editor.find('https://cdn.tiny.cloud')[0]!, 'TinyMCE');
    const { text } = editor.result();
    expect(changedLines(example, text)).toEqual({ removed: ['          status: pending'], added: ['          reason: TinyMCE'] });
  });

  it('turns a plain entry into an object when accepting it, keeping its comment', () => {
    const source = `version: 1
documents:
  app:
    routes: ["/"]
    directives:
      script-src:
        - self
        - unsafe-eval # needed by the template engine
`;
    const editor = new ConfigEditor(source);
    editor.accept(editor.find('unsafe-eval')[0]!, 'template engine');
    expect(editor.result().text).toContain(
      '        - value: unsafe-eval # needed by the template engine\n          reason: template engine\n',
    );
  });

  it('adds a plain source to a flow list and keeps it flow', () => {
    const editor = new ConfigEditor(example);
    editor.addSource({ kind: 'common' }, 'img-src', 'https://img.example.com');
    expect(changedLines(example, editor.result().text)).toEqual({
      removed: ['  img-src: [self]'],
      added: ['  img-src: [self, https://img.example.com]'],
    });
  });

  it('switches a flow list to block style when adding a source with metadata', () => {
    const editor = new ConfigEditor(example);
    editor.addSource({ kind: 'document', name: 'admin' }, 'connect-src', 'wss://live.example.com', { dev_only: true });
    expect(editor.result().text).toContain('      connect-src:\n        - self\n        - value: wss://live.example.com\n          dev_only: true\n');
  });

  it('creates a missing directive and writes keywords without quotes', () => {
    const editor = new ConfigEditor(example);
    editor.addSource({ kind: 'document', name: 'admin' }, 'frame-ancestors', "'none'");
    expect(editor.result().text).toContain('      frame-ancestors:\n        - none\n');
  });

  it('refuses duplicates and unknown documents', () => {
    const editor = new ConfigEditor(example);
    expect(() => editor.addSource({ kind: 'document', name: 'learning' }, 'script-src', "'self'")).toThrow(EditError);
    expect(() => editor.addSource({ kind: 'document', name: 'nope' }, 'script-src', 'self')).toThrow(/unknown document/);
  });

  it('refuses an edit that would make the file invalid', () => {
    const editor = new ConfigEditor(example);
    editor.addSource({ kind: 'document', name: 'admin' }, 'connect-src', 'https://${UNDEFINED}');
    expect(() => editor.result()).toThrow(/undefined variable/);
  });

  it('sets the mode of a document', () => {
    const editor = new ConfigEditor(example);
    editor.setMode('admin', 'enforce');
    expect(changedLines(example, editor.result().text)).toEqual({
      removed: ['    mode: report-only'],
      added: ['    mode: enforce'],
    });
  });
});

describe('canonicalValue', () => {
  it('strips quotes from keywords and rejects unknown ones', () => {
    expect(canonicalValue("'strict-dynamic'", 'script-src')).toBe('strict-dynamic');
    expect(canonicalValue('https://x.example.com', 'script-src')).toBe('https://x.example.com');
    expect(() => canonicalValue("'nope'", 'script-src')).toThrow();
  });
});

describe('acceptance', () => {
  it('treats a reason as acceptance unless the source is pending', () => {
    expect(isAccepted({ value: { kind: 'wildcard', text: '*' }, devOnly: false, reason: 'x' })).toBe(true);
    expect(isAccepted({ value: { kind: 'wildcard', text: '*' }, devOnly: false, reason: 'x', status: 'pending' })).toBe(false);
    expect(isAccepted({ value: { kind: 'wildcard', text: '*' }, devOnly: false })).toBe(false);
  });

  it('clears needs-reason after accept', () => {
    const editor = new ConfigEditor(example);
    editor.accept(editor.find('https://cdn.tiny.cloud')[0]!, 'TinyMCE');
    const parsed = parseConfig(editor.result().text);
    if (!parsed.ok) throw new Error('invalid');
    const tiny = evaluate(resolvePolicy(parsed.config, 'admin', 'prod'), { requireReason: 'medium' }).find(
      (w) => w.value === 'https://cdn.tiny.cloud',
    );
    expect(tiny).toMatchObject({ accepted: true, needsReason: false });
  });
});
