import { readFile } from 'node:fs/promises';
import { LineCounter, parseDocument } from 'yaml';
import type { $ZodIssue } from 'zod/v4/core';
import { InvalidValueError, parseSourceValue } from '../policy/values.js';
import { ConfigSchema, type Config, type DirectivesConfig } from './schema.js';

export type ConfigPath = (string | number)[];

export interface ConfigError {
  path: ConfigPath;
  message: string;
  line?: number;
}

export type LoadResult = { ok: true; config: Config } | { ok: false; errors: ConfigError[] };

export const DEFAULT_ENV = 'default';
const VARIABLE_REF = /\$\{([A-Za-z0-9_]+)\}/g;

export async function loadConfigFile(path: string): Promise<LoadResult> {
  return parseConfig(await readFile(path, 'utf8'));
}

export function parseConfig(source: string): LoadResult {
  const lineCounter = new LineCounter();
  const doc = parseDocument(source, { lineCounter, prettyErrors: false });

  const lineOf = (path: ConfigPath): number | undefined => {
    // Walk up until a node with a position is found (missing keys have none).
    for (let p = path; p.length > 0; p = p.slice(0, -1)) {
      const node = doc.getIn(p, true) as { range?: [number, number, number] } | undefined;
      if (node?.range) return lineCounter.linePos(node.range[0]).line;
    }
    return undefined;
  };
  const withLine = (e: Omit<ConfigError, 'line'>): ConfigError => ({ ...e, line: lineOf(e.path) });

  if (doc.errors.length > 0) {
    return {
      ok: false,
      errors: doc.errors.map((e) => ({
        path: [],
        message: e.message,
        line: e.linePos?.[0]?.line,
      })),
    };
  }

  const parsed = ConfigSchema.safeParse(doc.toJS());
  if (!parsed.success) {
    return { ok: false, errors: parsed.error.issues.map((i) => withLine(fromZodIssue(i))) };
  }

  const semantic = checkSemantics(parsed.data);
  if (semantic.length > 0) return { ok: false, errors: semantic.map(withLine) };
  return { ok: true, config: parsed.data };
}

function fromZodIssue(issue: $ZodIssue): Omit<ConfigError, 'line'> {
  return { path: issue.path.map((p) => (typeof p === 'symbol' ? String(p) : p)), message: issue.message };
}

/** Environments are the union of the environments named by variables. */
export function environmentsOf(config: Config): string[] {
  const envs = new Set<string>();
  for (const values of Object.values(config.variables)) {
    for (const env of Object.keys(values)) envs.add(env);
  }
  return envs.size > 0 ? [...envs].sort() : [DEFAULT_ENV];
}

function checkSemantics(config: Config): Omit<ConfigError, 'line'>[] {
  const errors: Omit<ConfigError, 'line'>[] = [];
  const envs = environmentsOf(config);

  for (const [name, values] of Object.entries(config.variables)) {
    for (const env of envs) {
      if (!(env in values)) {
        errors.push({ path: ['variables', name], message: `variable ${name} has no value for environment "${env}"` });
      }
    }
  }

  const checkDirectives = (directives: DirectivesConfig, base: ConfigPath) => {
    for (const [directive, entries] of Object.entries(directives)) {
      if (directive === 'upgrade-insecure-requests' && entries.length > 0) {
        errors.push({ path: [...base, directive], message: 'upgrade-insecure-requests takes no values, use []' });
      }
      entries.forEach((entry, i) => {
        const path = [...base, directive, i];
        const raw = typeof entry === 'string' ? entry : entry.value;
        for (const [, variable] of raw.matchAll(VARIABLE_REF)) {
          if (!(variable! in config.variables)) {
            errors.push({ path, message: `undefined variable \${${variable}}` });
          }
        }
        try {
          // Variables are substituted per environment later; validate the shape with a stand-in.
          parseSourceValue(raw.replace(VARIABLE_REF, 'var.invalid'), directive);
        } catch (e) {
          if (!(e instanceof InvalidValueError)) throw e;
          errors.push({ path, message: e.message });
        }
      });
    }
  };

  checkDirectives(config.common, ['common']);

  const routeOwner = new Map<string, string>();
  for (const [name, doc] of Object.entries(config.documents)) {
    if (name === 'common') {
      errors.push({ path: ['documents', name], message: '"common" is reserved for the shared block, rename this document' });
    }
    checkDirectives(doc.directives, ['documents', name, 'directives']);
    doc.routes.forEach((route, i) => {
      const owner = routeOwner.get(route);
      if (owner) {
        errors.push({
          path: ['documents', name, 'routes', i],
          message: `route ${route} already belongs to document "${owner}"`,
        });
      } else {
        routeOwner.set(route, name);
      }
    });
  }

  return errors;
}

export function substituteVariables(raw: string, config: Config, env: string): string {
  return raw.replace(VARIABLE_REF, (_, name: string) => config.variables[name]?.[env] ?? `\${${name}}`);
}
