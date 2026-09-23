#!/usr/bin/env node
import { Command, Option } from 'commander';
import { environmentsOf, loadConfigFile, type ConfigError } from './config/load.js';
import { PRIORITIES, type Priority } from './config/schema.js';
import { fetchLiveCsp } from './live.js';
import { reviewConfig, reviewLive, unresolvedAtLeast, type Report } from './report/review.js';
import { renderText } from './report/text.js';

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
  .action(async (opts: { config: string; env?: string; url?: string; header?: string; json?: boolean }) => {
    let report: Report;
    if (opts.url) {
      report = reviewLive(opts.url, await fetchLiveCsp(opts.url));
    } else if (opts.header) {
      report = reviewLive('header', { enforced: [opts.header], reportOnly: [], meta: [] });
    } else {
      report = await reviewFromConfig(opts.config, opts.env);
    }
    print(report, opts.json);
  });

program
  .command('check')
  .description('CI entry point: review csp.yml and fail on unresolved warnings at or above fail_on')
  .addOption(configOption())
  .addOption(envOption())
  .addOption(new Option('--fail-on <priority>', 'override settings.fail_on').choices(['none', ...PRIORITIES]))
  .option('--json', 'print the report as JSON')
  .action(async (opts: { config: string; env?: string; failOn?: 'none' | Priority; json?: boolean }) => {
    const loaded = await load(opts.config, opts.env);
    const report = reviewConfig(loaded, opts.config, opts.env);
    print(report, opts.json);

    const failOn = opts.failOn ?? loaded.settings.fail_on;
    if (failOn === 'none') return;
    const blocking = unresolvedAtLeast(report, failOn);
    if (blocking.length > 0) {
      console.error(`\ncheck failed: ${blocking.length} unresolved warning(s) at or above "${failOn}"`);
      process.exitCode = 1;
    }
  });

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

function print(report: Report, json?: boolean) {
  console.log(json ? JSON.stringify(report, null, 2) : renderText(report));
}

function fail(message: string): never {
  console.error(`cspgen: ${message}`);
  process.exit(2);
}

await program.parseAsync();
