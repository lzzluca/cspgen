import type { Priority } from '../config/schema.js';
import type { Report, ReportWarning } from './review.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint(31);
const yellow = paint(33);
const cyan = paint(36);
const dim = paint(2);
const bold = paint(1);

const PRIORITY_LABEL: Record<Priority, string> = {
  high: red('HIGH  '),
  medium: yellow('MEDIUM'),
  low: cyan('LOW   '),
};

export function renderText(report: Report): string {
  const out: string[] = [bold(`CSP review: ${report.target}`), ''];

  for (const doc of report.documents) {
    const routes = doc.routes.length > 0 ? `  ${dim(doc.routes.join(', '))}` : '';
    out.push(`${bold(`Document ${doc.document}`)}  mode: ${doc.mode}${routes}`);

    const showEnv = doc.headers.length > 1 || doc.headers[0]?.env !== 'live';
    for (const { env, headers } of doc.headers) {
      if (showEnv) out.push(`  ${dim(`[${env}]`)}`);
      for (const h of headers) out.push(`    ${h.name}: ${h.value}`);
    }

    if (doc.warnings.length === 0) {
      out.push('  No warnings.');
    } else {
      out.push('  Warnings:');
      for (const w of doc.warnings) out.push(...renderWarning(w, doc.headers.length));
    }
    out.push('');
  }

  for (const note of report.notes) out.push(yellow(`! ${note}`));
  if (report.notes.length > 0) out.push('');

  out.push(renderSummary(report));
  return out.join('\n');
}

function renderWarning(w: ReportWarning, envCount: number): string[] {
  const target = w.value ? `${w.directive} ${w.value}` : w.directive;
  const envs = envCount > 1 && w.envs.length < envCount ? dim(` [${w.envs.join(', ')}]`) : '';
  const state = w.accepted ? dim(' (accepted)') : w.needsReason ? red(' (needs reason)') : '';
  const lines = [`    ${PRIORITY_LABEL[w.priority]} ${bold(target)}${state}${envs}`, `           ${w.message}`];
  if (w.accepted && w.reason) lines.push(`           ${dim(`reason: ${w.reason}`)}`);
  return lines;
}

function renderSummary(report: Report): string {
  const all = report.documents.flatMap((d) => d.warnings);
  const count = (p: Priority) => {
    const of = all.filter((w) => w.priority === p);
    const accepted = of.filter((w) => w.accepted).length;
    return `${of.length} ${p}${accepted > 0 ? ` (${accepted} accepted)` : ''}`;
  };
  const open = all.filter((w) => !w.accepted && w.priority === 'high').length;
  const line = `Summary: ${count('high')}, ${count('medium')}, ${count('low')}`;
  if (open === 0) return bold(line);
  return `${bold(line)}\n${red(bold(`⚠ ${open} unresolved HIGH-priority warning${open === 1 ? '' : 's'}: this policy leaves significant XSS risk open.`))}`;
}
