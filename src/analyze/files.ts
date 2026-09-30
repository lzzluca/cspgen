import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { findCandidates } from './candidates.js';

// Which files are sent to the LLM. Deterministic: only files tracked by git
// (so .env and anything ignored never leave the machine), minus dependencies,
// build output, lockfiles and docs. Frontend and template files always go;
// any other file only when a candidate pattern matches.

const EXCLUDED_DIRS = new Set([
  'node_modules',
  'deps',
  '_build',
  'dist',
  'build',
  'out',
  'vendor',
  'coverage',
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.venv',
  '__pycache__',
]);

const FRONTEND_EXTENSIONS = new Set([
  '.html', '.htm', '.heex', '.leex', '.eex', '.erb', '.haml', '.slim', '.ejs', '.hbs', '.njk', '.twig',
  '.jinja', '.j2', '.liquid', '.php', '.cshtml', '.razor', '.jsp',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx', '.vue', '.svelte', '.astro',
  '.css', '.scss', '.sass', '.less',
]);

/** Never analyzed: dependency locks, docs, data, and cspgen's own files (full of URLs, none loaded by the app). */
const EXCLUDED_FILES = [
  /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|mix\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|composer\.lock|go\.sum)$/,
  /(^|\/)(csp\.yml|csp\.lock|csp\.observations\.yml|csp\.schema\.json)$/,
  /(^|\/)(LICEN[CS]E|CHANGELOG|AUTHORS)[^/]*$/i,
  /\.(md|mdx|markdown|txt|rst|adoc|csv|tsv|sql|svg|map|snap|min\.js|min\.css)$/i,
  /\.(png|jpe?g|gif|webp|ico|avif|bmp|pdf|woff2?|ttf|otf|eot|mp3|mp4|webm|mov|wav|zip|gz|tgz|jar|wasm)$/i,
];

/** Files larger than this are almost always generated or vendored. */
export const MAX_FILE_BYTES = 256 * 1024;

export interface SelectedFile {
  path: string;
  content: string;
}

export async function listTrackedFiles(root: string): Promise<string[]> {
  try {
    const { stdout } = await promisify(execFile)('git', ['ls-files', '-z', '--cached'], {
      cwd: root,
      maxBuffer: 64 * 1024 * 1024,
    });
    return stdout.split('\0').filter((p) => p.length > 0);
  } catch (e) {
    throw new Error(`${root} is not a git repository (cspgen analyzes only files tracked by git): ${(e as Error).message}`);
  }
}

/** First filter, on the path alone. */
export function isExcludedPath(path: string, exclude: string[] = []): boolean {
  if (path.split('/').slice(0, -1).some((dir) => EXCLUDED_DIRS.has(dir))) return true;
  if (EXCLUDED_FILES.some((re) => re.test(path))) return true;
  return exclude.some((glob) => globToRegExp(glob).test(path));
}

export function isFrontendFile(path: string): boolean {
  const dot = path.lastIndexOf('.');
  return dot > path.lastIndexOf('/') && FRONTEND_EXTENSIONS.has(path.slice(dot).toLowerCase());
}

/** Second filter, on the content: frontend files always, others only with a candidate. */
export function shouldAnalyze(path: string, content: string): boolean {
  if (content.includes('\0')) return false;
  return isFrontendFile(path) || findCandidates(content).length > 0;
}

export async function selectFiles(
  root: string,
  exclude: string[],
  read: (path: string) => Promise<string | undefined>,
): Promise<SelectedFile[]> {
  const selected: SelectedFile[] = [];
  for (const path of (await listTrackedFiles(root)).sort()) {
    if (isExcludedPath(path, exclude)) continue;
    const content = await read(path);
    if (content === undefined || content.length > MAX_FILE_BYTES) continue;
    if (shouldAnalyze(path, content)) selected.push({ path, content });
  }
  return selected;
}

/** Minimal globs: `**` any path, `*` any name part, `?` one character. A glob without `/` matches at any depth. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        re += '(?:.*/)?';
      } else {
        re += '.*';
      }
    } else if (c === '*') {
      re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const anchored = glob.includes('/') ? `^${re}` : `(^|/)${re}`;
  return new RegExp(`${anchored}(/.*)?$`);
}
