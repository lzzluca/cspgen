#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { Command, Option } from 'commander';
import { ConfigEditor, EditError, scopeLabel, type Scope } from './config/edit.js';
import { environmentsOf, loadConfigFile, parseConfig, type ConfigError } from './config/load.js';
import { DIRECTIVES, PRIORITIES, type Directive, type Priority } from './config/schema.js';
import { fetchLiveCsp } from './live.js';
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
  .action(async (opts: { config: string; env?: string; failOn?: 'none' | Priority; json?: boolean; verbose?: boolean }) => {
    const loaded = await load(opts.config, opts.env);
    const report = reviewConfig(loaded, opts.config, opts.env);
    print(report, opts);

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
    const report = reviewConfig(config, opts.config);
    const open = report.documents.find((d) => d.document === document)!.warnings.filter((w) => !w.accepted && w.needsReason);
    if (open.length > 0) {
      console.log(`Heads-up: ${document} still has ${open.length} unresolved warning(s) that need a reason:`);
      for (const w of open) console.log(`  ${w.priority.toUpperCase()} ${w.directive}${w.value ? ` ${w.value}` : ''}`);
      console.log('');
    }
    await editConfig(opts.config, opts.dryRun, (editor) => editor.setMode(document, 'enforce'));
  });

function parseScope(name: string): Scope {
  return name === 'common' ? { kind: 'common' } : { kind: 'document', name };
}

async function editConfig(path: string, dryRun: boolean | undefined, edit: (editor: ConfigEditor) => void) {
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
    console.log(`\n(dry run: ${path} not modified)`);
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
