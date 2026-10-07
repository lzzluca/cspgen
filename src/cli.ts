#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { Command, Option } from 'commander';
import { analyze, isReusable, isStale, staleness, type AnalyzeResult, type Staleness } from './analyze/analyze.js';
import { findCandidates } from './analyze/candidates.js';
import { selectFiles } from './analyze/files.js';
import { isLocal, openAiCompatible } from './analyze/llm.js';
import { hashContent, readLock, serializeLock, type LockFile, type LockFinding } from './analyze/lock.js';
import { buildMessages, windowsOf } from './analyze/prompt.js';
import { ConfigEditor, EditError, scopeLabel, type Scope } from './config/edit.js';
import { environmentsOf, loadConfigFile, parseConfig, type ConfigError } from './config/load.js';
import { DIRECTIVES, PRIORITIES, type AnalysisConfig, type Directive, type Priority } from './config/schema.js';
import { fetchLiveCsp } from './live.js';
import { parseSourceValue } from './policy/values.js';
import { mergeObservations, readObservations, serializeObservations } from './observations.js';
import { analyzeViolations, fallbackSeed, type ImportAnalysis } from './reports/import.js';
import { parseReports, ReportFormatError, type Violation } from './reports/parse.js';
import { reviewConfig, reviewLive, unresolvedAtLeast, type Report } from './report/review.js';
import { renderDiff, renderText } from './report/text.js';

const program = new Command()
  .name('cspgen')
  .description('Generate, review and check the Content Security Policy of a web app')
  .version('0.1.0');

const configOption = () => new Option('-c, --config <path>', 'path to csp.yml').default('csp.yml');
const envOption = () => new Option('-e, --env <name>', 'environment (default: all)').env('CSPGEN_ENV');

program
  .command('review')
  .description('Evaluate csp.yml, a live URL or a header value against the strictest CSP')
  .addOption(configOption())
  .addOption(envOption())
  .option('-u, --url <url>', 'review the policy served by a live URL instead of csp.yml')
  .option('-H, --header <value>', 'review a Content-Security-Policy header value')
  .option('--json', 'print the report as JSON')
  .option('-v, --verbose', 'list every low-priority warning instead of grouping them')
  .action(async (opts: { config: string; env?: string; url?: string; header?: string; json?: boolean; verbose?: boolean }) => {
    let report: Report;
    if (opts.url) {
      report = reviewLive(opts.url, await fetchLiveCsp(opts.url));
    } else if (opts.header) {
      report = reviewLive('header', { enforced: [opts.header], reportOnly: [], meta: [] });
    } else {
      report = await reviewFromConfig(opts.config, opts.env);
    }
    print(report, opts);
  });

program
  .command('check')
  .description('CI entry point: review csp.yml and fail on unresolved warnings at or above fail_on')
  .addOption(configOption())
  .addOption(envOption())
  .addOption(new Option('--fail-on <priority>', 'override settings.fail_on').choices(['none', ...PRIORITIES]))
  .option('--json', 'print the report as JSON')
  .option('-v, --verbose', 'list every low-priority warning instead of grouping them')
  .option('--root <dir>', 'repository analyzed by `cspgen analyze` (default: the folder of csp.yml)')
  .action(async (opts: { config: string; env?: string; failOn?: 'none' | Priority; json?: boolean; verbose?: boolean; root?: string }) => {
    const loaded = await load(opts.config, opts.env);
    const report = reviewConfig(loaded, opts.config, opts.env);
    print(report, opts);

    // The lock only warns: it is a cache of the analysis, and CI never calls the LLM.
    if (loaded.analysis) {
      const { files, previous } = await filesToAnalyze(opts.config, loaded.analysis, opts.root);
      const stale = staleness(files, previous, loaded.analysis.model);
      if (isStale(stale)) console.warn(`
${describeStaleness(stale)}`);
    }

    const failOn = opts.failOn ?? loaded.settings.fail_on;
    if (failOn === 'none') return;
    const blocking = unresolvedAtLeast(report, failOn);
    if (blocking.length > 0) {
      console.error(`\ncheck failed: ${blocking.length} unresolved warning(s) at or above "${failOn}"`);
      process.exitCode = 1;
    }
  });

const dryRunOption = () => new Option('-n, --dry-run', 'show the change without writing csp.yml');

program
  .command('accept')
  .description('Accept a source in csp.yml by giving the reason it is needed')
  .argument('<value>', "the source, e.g. unsafe-inline or https://cdn.tiny.cloud")
  .requiredOption('-r, --reason <text>', 'why the source is needed')
  .option('-d, --directive <name>', 'only look in this directive')
  .option('-D, --document <name>', 'only look in this document (or "common")')
  .addOption(configOption())
  .addOption(dryRunOption())
  .action(async (value: string, opts: { reason: string; directive?: string; document?: string; config: string; dryRun?: boolean }) => {
    await editConfig(opts.config, opts.dryRun, (editor) => {
      const scope = opts.document ? parseScope(opts.document) : undefined;
      const found = editor.find(value, { directive: opts.directive, scope });
      if (found.length === 0) {
        throw new EditError(`${value} not found in csp.yml; use \`cspgen add-source\` to add it`);
      }
      if (found.length > 1) {
        const where = found.map((l) => `  ${scopeLabel(l.scope)} ${l.directive}`).join('\n');
        throw new EditError(`${value} appears in several places, narrow it with --document and --directive:\n${where}`);
      }
      editor.accept(found[0]!, opts.reason);
    });
  });

program
  .command('add-source')
  .description('Add a source to a directive of a document (or of the common block)')
  .argument('<value>', "the source, e.g. https://js.stripe.com or self")
  .addOption(new Option('-d, --directive <name>', 'directive').choices(DIRECTIVES).makeOptionMandatory())
  .requiredOption('-D, --document <name>', 'document name, or "common" for every document')
  .option('-r, --reason <text>', 'why the source is needed (accepts it)')
  .option('--dev-only', 'only include the source in dev environments')
  .addOption(configOption())
  .addOption(dryRunOption())
  .action(
    async (value: string, opts: { directive: Directive; document: string; reason?: string; devOnly?: boolean; config: string; dryRun?: boolean }) => {
      await editConfig(opts.config, opts.dryRun, (editor) =>
        editor.addSource(parseScope(opts.document), opts.directive, value, { reason: opts.reason, dev_only: opts.devOnly }),
      );
    },
  );

program
  .command('promote')
  .description('Switch a document from report-only to enforce')
  .argument('<document>', 'document name')
  .addOption(configOption())
  .addOption(dryRunOption())
  .action(async (document: string, opts: { config: string; dryRun?: boolean }) => {
    const config = await load(opts.config);
    if (!config.documents[document]) fail(`unknown document "${document}"`);
    if (config.documents[document].mode === 'enforce') {
      console.log(`Document ${document} is already enforced.`);
      return;
    }
    // Before enforcing, list what nobody decided on yet: warnings needing a reason, then pending sources.
    const report = reviewConfig(config, opts.config);
    const toReview = report.documents
      .find((d) => d.document === document)!
      .warnings.filter((w) => !w.accepted && w.needsReason)
      .map((w) => ({ label: w.priority.toUpperCase(), directive: w.directive, value: w.value ?? '' }));
    for (const [directive, entries] of Object.entries(config.documents[document].directives)) {
      for (const e of entries) {
        if (typeof e === 'string' || e.status !== 'pending') continue;
        const text = parseSourceValue(e.value, directive).text;
        if (!toReview.some((r) => r.directive === directive && r.value === text)) {
          toReview.push({ label: 'PENDING', directive, value: text });
        }
      }
    }
    if (toReview.length > 0) {
      console.log(`Heads-up: ${document} has ${toReview.length} item(s) nobody decided on yet:`);
      for (const r of toReview) console.log(`  ${r.label.padEnd(7)} ${r.directive} ${r.value}`.trimEnd());
      console.log('');
    }
    await editConfig(opts.config, opts.dryRun, (editor) => editor.setMode(document, 'enforce'));
  });

program
  .command('import-reports')
  .description('Import CSP violation reports (report-uri or Reporting API JSON, or NDJSON) and propose the missing sources')
  .argument('<files...>', 'report files')
  .addOption(configOption())
  .option('--observations <path>', 'observations file (default: csp.observations.yml next to csp.yml)')
  .option('--min-count <n>', 'only propose sources seen at least n times', (v) => Number.parseInt(v, 10), 1)
  .option('-w, --write', 'apply the patch to csp.yml and record the observations')
  .action(async (files: string[], opts: { config: string; observations?: string; minCount: number; write?: boolean }) => {
    const config = await load(opts.config);
    const violations: Violation[] = [];
    let skipped = 0;
    for (const file of files) {
      try {
        const parsed = parseReports(await readFile(file, 'utf8'));
        violations.push(...parsed.violations);
        skipped += parsed.skipped;
      } catch (e) {
        if (e instanceof ReportFormatError) fail(`${file}: ${e.message}`);
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') fail(`${file} not found`);
        throw e;
      }
    }

    const analysis = analyzeViolations(config, violations);
    printImportSummary(analysis, skipped, opts.minCount);
    const toAdd = analysis.proposals.filter((p) => !p.alreadyAllowed && p.count >= opts.minCount);

    if (toAdd.length > 0) {
      console.log('');
      await editConfig(
        opts.config,
        !opts.write,
        (editor) => {
          const seeded = new Set<string>();
          for (const p of toAdd) {
            const scope = { kind: 'document' as const, name: p.document };
            const key = `${p.document}|${p.directive}`;
            if (!seeded.has(key)) {
              seeded.add(key);
              for (const raw of fallbackSeed(config, p.document, p.directive)) editor.addSource(scope, p.directive, raw);
            }
            editor.addSource(scope, p.directive, p.source, { status: 'pending' });
          }
        },
        'Nothing written. Run again with --write to apply the patch and record the observations.',
      );
    }

    if (opts.write && analysis.proposals.length > 0) {
      const path = opts.observations ?? join(dirname(opts.config), 'csp.observations.yml');
      const merged = mergeObservations(await readObservations(path), analysis.proposals, 'production-report', new Date());
      await writeFile(path, serializeObservations(merged));
      console.log(`Recorded ${analysis.proposals.length} observation(s) in ${path}.`);
    }
  });

program
  .command('analyze')
  .description('Ask the LLM what the code loads, check every answer against the code, and update csp.lock')
  .addOption(configOption())
  .option('--root <dir>', 'repository to analyze (default: the folder of csp.yml)')
  .option('-m, --model <name>', 'override analysis.model for this run')
  .option('-n, --dry-run', 'print what would be sent to the LLM, without sending it or writing csp.lock')
  .action(async (opts: { config: string; root?: string; model?: string; dryRun?: boolean }) => {
    const config = await load(opts.config);
    if (!config.analysis) {
      fail(`${opts.config} has no analysis section; add one, e.g.\n\nanalysis:\n  base_url: http://localhost:11434/v1   # Ollama\n  model: gemma4:12b`);
    }
    const { base_url: baseUrl } = config.analysis;
    const model = opts.model ?? config.analysis.model;
    const { root, lockPath, files, previous } = await filesToAnalyze(opts.config, config.analysis, opts.root);
    if (opts.model && opts.model !== config.analysis.model) {
      console.warn(`warning: using ${opts.model} instead of ${config.analysis.model} (csp.yml); the lock will record ${opts.model}`);
    }
    const todo = files.filter((f) => !isReusable(previous, model, f.path, hashContent(f.content)));

    if (opts.dryRun) {
      console.log(`${files.length} file(s) selected in ${root}, ${todo.length} to send to ${baseUrl} (model ${model}):\n`);
      for (const f of todo) {
        const lines = f.content.split('\n');
        for (const w of windowsOf(f.content, findCandidates(f.content))) {
          for (const m of buildMessages(f.path, lines.length, w).filter((m) => m.role === 'user')) {
            console.log(`${'='.repeat(78)}\n${m.content}\n`);
          }
        }
      }
      console.log(`(dry run: nothing sent, ${lockPath} not modified; the system prompt is the same for every file)`);
      return;
    }

    const where = isLocal(baseUrl) ? 'on this machine' : 'to a remote service';
    console.log(`Sending code ${where}: ${baseUrl}, model ${model}. Only files tracked by git are sent; see them with --dry-run.`);
    const client = openAiCompatible({
      baseUrl,
      model,
      apiKey: process.env.CSPGEN_API_KEY,
      reasoningEffort: config.analysis.reasoning_effort,
    });
    const result = await analyze(files, client, previous, (p) => {
      if (p.type === 'start') process.stdout.write(`  [${p.index}/${p.total}] ${p.path} … `);
      else console.log(describeFile(p.file));
    });
    if (result.invalidated) console.log(`Analyzed every file again: ${result.invalidated}.`);

    await writeFile(lockPath, serializeLock(result.lock));
    printAnalyzeSummary(result, lockPath);
  });

async function filesToAnalyze(configPath: string, analysis: AnalysisConfig, rootOption?: string) {
  const root = resolve(rootOption ?? dirname(configPath));
  const lockPath = join(dirname(configPath), 'csp.lock');
  try {
    const files = await selectFiles(root, analysis.exclude, (path) => readFile(join(root, path), 'utf8').catch(() => undefined));
    return { root, lockPath, files, previous: await readLock(lockPath) };
  } catch (e) {
    fail((e as Error).message);
  }
}

function describeStaleness(s: Staleness): string {
  const list = (label: string, paths: string[]) =>
    paths.length === 0 ? [] : [`  ${label}: ${paths.slice(0, 5).join(', ')}${paths.length > 5 ? `, … (${paths.length})` : ''}`];
  const lines = [
    `warning: csp.lock is out of date${s.reason ? `: ${s.reason}` : ''}. Run \`cspgen analyze\`.`,
    ...list('changed since the last analysis', s.changed),
    ...list('new', s.added),
    ...list('no longer analyzed', s.removed),
    ...list('analysis failed', s.errors),
  ];
  return lines.join('\n');
}

function describeFile(f: LockFile): string {
  if (f.status === 'error') return `error: ${f.error}`;
  const unverified = f.findings.filter((x) => !x.verified).length;
  const missed = f.findings.filter((x) => x.missed_by_llm).length;
  const parts = [`${f.findings.length} finding(s)`];
  if (unverified > 0) parts.push(`${unverified} unverified`);
  if (missed > 0) parts.push(`${missed} missed by the LLM`);
  if (f.dismissed.length > 0) parts.push(`${f.dismissed.length} dismissed`);
  return parts.join(', ');
}

function printAnalyzeSummary(result: AnalyzeResult, lockPath: string) {
  const entries = Object.entries(result.lock.files);
  const all = entries.flatMap(([path, f]) => f.findings.map((finding) => ({ path, finding })));
  const errors = entries.filter(([, f]) => f.status === 'error');
  const line = (path: string, x: LockFinding) =>
    `  ${path}:${x.evidence.line}  ${x.kind}${x.source ? ` ${x.source}` : ''}${x.directive ? ` (${x.directive})` : ''}`;

  console.log(
    `\n${result.analyzed.length} file(s) analyzed, ${result.reused.length} unchanged (answers reused). ` +
      `${all.length} finding(s) in ${entries.length} file(s).`,
  );
  const verified = all.filter((x) => x.finding.verified && !x.finding.missed_by_llm);
  if (verified.length > 0) {
    console.log(`\nVerified (the cited code exists):`);
    for (const { path, finding } of verified) console.log(`${line(path, finding)}${finding.dev_only ? '  dev only' : ''}`);
  }
  const missed = all.filter((x) => x.finding.missed_by_llm);
  if (missed.length > 0) {
    console.log(`\nMissed by the LLM (found by pattern matching, not reported or not judged):`);
    for (const { path, finding } of missed) console.log(line(path, finding));
  }
  const unverified = all.filter((x) => !x.finding.verified);
  if (unverified.length > 0) {
    console.log(`\nUnverified, for you to look at (not proposed for the policy):`);
    for (const { path, finding } of unverified) console.log(`${line(path, finding)}\n      ${finding.unverified_reason}`);
  }
  if (errors.length > 0) {
    console.log(`\nNot analyzed (run again to retry):`);
    for (const [path, f] of errors) console.log(`  ${path}: ${f.error}`);
  }
  console.log(`\nWrote ${lockPath}.`);
}

function printImportSummary(analysis: ImportAnalysis, skipped: number, minCount: number) {
  const n = (x: number) => x.toLocaleString('en-US');
  console.log(`Read ${n(analysis.total)} CSP violation report(s)${skipped > 0 ? ` (${n(skipped)} other entries skipped)` : ''}.`);
  if (analysis.noise > 0) console.log(`  ignored ${n(analysis.noise)} caused by browser extensions or the browser itself`);
  if (analysis.unsupported > 0) console.log(`  ignored ${n(analysis.unsupported)} that do not map to a CSP source`);
  if (analysis.unmatched.size > 0) {
    const paths = [...analysis.unmatched].sort((a, b) => b[1] - a[1]);
    const total = paths.reduce((sum, [, c]) => sum + c, 0);
    const shown = paths.slice(0, 5).map(([p, c]) => `${p} (${n(c)})`).join(', ');
    console.log(`  ${n(total)} on pages no document route matches: ${shown}${paths.length > 5 ? ', …' : ''}`);
  }

  const fresh = analysis.proposals.filter((p) => !p.alreadyAllowed);
  const allowed = analysis.proposals.filter((p) => p.alreadyAllowed);
  if (fresh.length === 0) {
    console.log('\nNo new sources: every reported source is already allowed.');
  } else {
    console.log(`\nSources missing from the policy (most frequent first):`);
    for (const p of fresh) {
      const below = p.count < minCount ? '  (below --min-count, not proposed)' : '';
      const examples = p.examples.length > 0 ? `  e.g. ${p.examples.join(', ')}` : '';
      console.log(`  ${n(p.count).padStart(7)}×  ${p.document}  ${p.directive} ${p.source}${examples}${below}`);
    }
  }
  if (allowed.length > 0) {
    console.log(`\n${allowed.length} reported source(s) are already allowed (reports from an older policy or cached pages).`);
  }
}

function parseScope(name: string): Scope {
  return name === 'common' ? { kind: 'common' } : { kind: 'document', name };
}

async function editConfig(
  path: string,
  dryRun: boolean | undefined,
  edit: (editor: ConfigEditor) => void,
  notWrittenHint = `(dry run: ${path} not modified)`,
) {
  const original = await readFile(path, 'utf8').catch((e: NodeJS.ErrnoException) => {
    if (e.code === 'ENOENT') fail(`${path} not found`);
    throw e;
  });
  const before = parseConfig(original);
  if (!before.ok) fail(`${path} is invalid, fix it first:\n${before.errors.map((e) => formatError(path, e)).join('\n')}`);

  const editor = new ConfigEditor(original);
  let result: { text: string; changed: boolean };
  try {
    edit(editor);
    result = editor.result();
  } catch (e) {
    if (e instanceof EditError) fail(e.message);
    throw e;
  }
  if (!result.changed) {
    console.log('Nothing to change.');
    return;
  }
  console.log(renderDiff(editor.diff(path)));
  if (dryRun) {
    console.log(`\n${notWrittenHint}`);
    return;
  }
  await writeFile(path, result.text);
  console.log(`\nUpdated ${path}.`);
}

async function reviewFromConfig(path: string, env?: string): Promise<Report> {
  return reviewConfig(await load(path, env), path, env);
}

async function load(path: string, env?: string) {
  const result = await loadConfigFile(path).catch((e: NodeJS.ErrnoException) => {
    if (e.code === 'ENOENT') fail(`${path} not found`);
    throw e;
  });
  if (!result.ok) fail(`${path} is invalid:\n${result.errors.map((e) => formatError(path, e)).join('\n')}`);
  const { config } = result;
  if (env && !environmentsOf(config).includes(env)) {
    fail(`unknown environment "${env}" (known: ${environmentsOf(config).join(', ')})`);
  }
  return config;
}

function formatError(file: string, e: ConfigError): string {
  const where = e.line ? `${file}:${e.line}` : file;
  const path = e.path.length > 0 ? ` ${e.path.join('.')}:` : '';
  return `  ${where}${path} ${e.message}`;
}

function print(report: Report, opts: { json?: boolean; verbose?: boolean }) {
  console.log(opts.json ? JSON.stringify(report, null, 2) : renderText(report, { verbose: opts.verbose }));
}

function fail(message: string): never {
  console.error(`cspgen: ${message}`);
  process.exit(2);
}

await program.parseAsync();
