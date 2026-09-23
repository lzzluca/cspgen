import { createPatch } from 'diff';
import { isMap, isScalar, isSeq, parseDocument, Scalar, YAMLMap, YAMLSeq, type Document } from 'yaml';
import { InvalidValueError, parseSourceValue } from '../policy/values.js';
import { parseConfig, type ConfigError, type ConfigPath } from './load.js';
import type { Directive } from './schema.js';

// Edits csp.yml in place, preserving comments, order and formatting of
// everything that is not touched, so patches produce minimal diffs.

const TO_STRING = { flowCollectionPadding: false, lineWidth: 0 } as const;

/** Where a source lives: a document, or the common block shared by all documents. */
export type Scope = { kind: 'common' } | { kind: 'document'; name: string };

export interface SourceLocation {
  scope: Scope;
  directive: string;
  index: number;
}

export interface SourceMeta {
  status?: 'pending';
  reason?: string;
  dev_only?: boolean;
}

export class EditError extends Error {}

export function scopeLabel(scope: Scope): string {
  return scope.kind === 'common' ? 'common' : scope.name;
}

function scopePath(scope: Scope): ConfigPath {
  return scope.kind === 'common' ? ['common'] : ['documents', scope.name, 'directives'];
}

/** Canonical form written by the tool: keywords without quotes (`self`, not `'self'`). */
export function canonicalValue(raw: string, directive: string): string {
  const trimmed = raw.trim();
  const quoted = trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'");
  if (!quoted) return trimmed;
  parseSourceValue(trimmed, directive); // throws on unknown keywords
  return trimmed.slice(1, -1);
}

/** Two raw values are the same source if they normalize to the same header text. */
function sameSource(a: string, b: string, directive: string): boolean {
  try {
    return parseSourceValue(a, directive).text === parseSourceValue(b, directive).text;
  } catch (e) {
    if (e instanceof InvalidValueError) return a.trim() === b.trim();
    throw e;
  }
}

export class ConfigEditor {
  private readonly doc: Document;

  constructor(private readonly original: string) {
    this.doc = parseDocument(original);
  }

  /** All places where a source value appears, optionally restricted to one directive or scope. */
  find(value: string, filter: { directive?: string; scope?: Scope } = {}): SourceLocation[] {
    const scopes: Scope[] = filter.scope ? [filter.scope] : [{ kind: 'common' }, ...this.documentNames().map((name) => ({ kind: 'document' as const, name }))];
    const found: SourceLocation[] = [];
    for (const scope of scopes) {
      const directives = this.doc.getIn(scopePath(scope));
      if (!isMap(directives)) continue;
      for (const pair of directives.items) {
        const directive = String(isScalar(pair.key) ? pair.key.value : pair.key);
        if (filter.directive && directive !== filter.directive) continue;
        if (!isSeq(pair.value)) continue;
        pair.value.items.forEach((item, index) => {
          const raw = entryValue(item);
          if (raw !== undefined && sameSource(raw, value, directive)) found.push({ scope, directive, index });
        });
      }
    }
    return found;
  }

  documentNames(): string[] {
    const documents = this.doc.get('documents');
    if (!isMap(documents)) return [];
    return documents.items.map((pair) => String(isScalar(pair.key) ? pair.key.value : pair.key));
  }

  /** Sets a reason on an existing source, which accepts it (and clears a pending status). */
  accept(location: SourceLocation, reason: string): void {
    const seq = this.seqAt(location);
    const item = seq.items[location.index];
    const raw = entryValue(item);
    if (raw === undefined) throw new EditError('source not found');

    if (isMap(item)) {
      item.delete('status');
      item.set('reason', reason);
    } else {
      seq.items[location.index] = this.entryNode(raw, { reason }, item as Scalar);
      seq.flow = false;
    }
  }

  addSource(scope: Scope, directive: Directive, value: string, meta: SourceMeta = {}): void {
    if (scope.kind === 'document' && !this.documentNames().includes(scope.name)) {
      throw new EditError(`unknown document "${scope.name}"`);
    }
    if (this.find(value, { directive, scope }).length > 0) {
      throw new EditError(`${value} is already in ${directive} of ${scopeLabel(scope)}`);
    }
    const canonical = canonicalValue(value, directive);
    const hasMeta = meta.status !== undefined || meta.reason !== undefined || meta.dev_only;
    const node = hasMeta ? this.entryNode(canonical, meta) : this.doc.createNode(canonical);

    const path = [...scopePath(scope), directive];
    const seq = this.doc.getIn(path);
    if (isSeq(seq)) {
      seq.items.push(node);
      if (hasMeta) seq.flow = false;
    } else {
      this.doc.setIn(path, new YAMLSeq());
      (this.doc.getIn(path) as YAMLSeq).items.push(node);
    }
  }

  setMode(document: string, mode: 'report-only' | 'enforce'): void {
    if (!this.documentNames().includes(document)) throw new EditError(`unknown document "${document}"`);
    this.doc.setIn(['documents', document, 'mode'], mode);
  }

  toString(): string {
    return this.doc.toString(TO_STRING);
  }

  /** The edited text, validated: an edit must never produce an invalid csp.yml. */
  result(): { text: string; changed: boolean } {
    const text = this.toString();
    const parsed = parseConfig(text);
    if (!parsed.ok) {
      throw new EditError(`edit would make the file invalid:\n${parsed.errors.map(formatError).join('\n')}`);
    }
    return { text, changed: text !== this.original };
  }

  diff(fileName: string): string {
    return createPatch(fileName, this.original, this.toString(), '', '', { context: 3 });
  }

  private seqAt(location: SourceLocation): YAMLSeq {
    const seq = this.doc.getIn([...scopePath(location.scope), location.directive]);
    if (!isSeq(seq)) throw new EditError(`no ${location.directive} in ${scopeLabel(location.scope)}`);
    return seq;
  }

  private entryNode(value: string, meta: SourceMeta, replaced?: Scalar): YAMLMap {
    const map = new YAMLMap();
    const valueNode = new Scalar(value);
    map.set('value', valueNode);
    if (meta.status) map.set('status', meta.status);
    if (meta.reason) map.set('reason', meta.reason);
    if (meta.dev_only) map.set('dev_only', true);
    // Keep the comments of the scalar being replaced: the line comment stays next to the value.
    if (replaced) {
      map.commentBefore = replaced.commentBefore;
      valueNode.comment = replaced.comment;
    }
    return map;
  }
}

function entryValue(item: unknown): string | undefined {
  if (isScalar(item) && typeof item.value === 'string') return item.value;
  if (isMap(item)) {
    const value = item.get('value');
    return typeof value === 'string' ? value : undefined;
  }
  return undefined;
}

function formatError(e: ConfigError): string {
  return `  ${e.line ? `line ${e.line}: ` : ''}${e.path.join('.')} ${e.message}`;
}
