import { z } from 'zod';
import { DIRECTIVES } from '../config/schema.js';
import { FINDING_KINDS, type Candidate } from './candidates.js';
import type { ChatMessage } from './llm.js';

// The one question asked for each file (or window of a long file). Bump
// PROMPT_VERSION whenever the prompt or the answer schema changes: it is
// recorded in csp.lock and invalidates every cached answer.

export const PROMPT_VERSION = 1;

export const WINDOW_LINES = 300;
export const WINDOW_OVERLAP = 20;

export const AnswerSchema = z.object({
  findings: z.array(
    z.object({
      kind: z.enum(FINDING_KINDS),
      source: z.string(),
      directive: z.enum(DIRECTIVES),
      line: z.number().int().positive(),
      text: z.string(),
      provenance: z.string().optional(),
      dev_only: z.boolean().optional(),
    }),
  ),
  candidates: z.array(z.object({ id: z.string(), relevant: z.boolean(), reason: z.string() })),
});

export type Answer = z.output<typeof AnswerSchema>;
export type AnswerFinding = Answer['findings'][number];

export const ANSWER_JSON_SCHEMA = { name: 'csp_findings', schema: z.toJSONSchema(AnswerSchema) };

const SYSTEM = `You analyze one file of a web application to build its Content Security Policy (CSP).

Report only what a BROWSER loads or runs when it shows a page of the application:
scripts, stylesheets, images, fonts, media, fetch/XHR/WebSocket/EventSource connections,
iframes, workers, form targets. Code that runs on the server (API clients, database,
calls from the backend to other services), build tools and tests are NOT relevant:
the browser never contacts those hosts.

Finding kinds:
- external-source: something loaded from a URL. "source" is the origin
  (https://cdn.example.com), or "self" for relative paths and the app's own origin.
  For the other kinds, "source" is an empty string.
  For URLs built at runtime, write the dynamic part as \${NAME}, e.g. wss://\${API_HOST}.
- inline-script: a <script> element without src in HTML or a template.
- inline-style: a <style> element or a style="..." attribute in HTML or a template.
  NOT JSX style={{...}} props: they go through the DOM API, which CSP does not block.
- inline-handler: an event handler attribute such as onclick="..." in HTML or a template.
  NOT JSX onClick={...} props.
- eval: eval(), new Function(), setTimeout/setInterval with a string.

For every finding:
- "line" is the line number shown before the code.
- "text" is copied VERBATIM from that line: the exact code containing the source. Never paraphrase.
- "directive" is the CSP directive that governs it (script-src, style-src, img-src, connect-src...).
- "provenance" says briefly what it is (e.g. "Stripe checkout", "app bundle").
- "dev_only" is true when it is only used in development (localhost, dev server, live reload).

You also get a list of candidates found by pattern matching. For EVERY candidate id,
say whether it is relevant to the CSP, with a short reason. Relevant candidates must
also appear in "findings". Not relevant examples: a URL only used by server-side code,
a link in a comment, an XML namespace.

If nothing in the file is relevant, return empty lists. Answer with JSON only.`;

export interface Window {
  start: number;
  end: number;
  lines: string[];
  candidates: Candidate[];
}

/** Splits a file into overlapping windows of numbered lines, each with its candidates. */
export function windowsOf(content: string, candidates: Candidate[]): Window[] {
  const lines = content.split('\n');
  const windows: Window[] = [];
  for (let start = 1; ; start += WINDOW_LINES - WINDOW_OVERLAP) {
    const end = Math.min(lines.length, start + WINDOW_LINES - 1);
    windows.push({
      start,
      end,
      lines: lines.slice(start - 1, end),
      candidates: candidates.filter((c) => c.line >= start && c.line <= end),
    });
    if (end >= lines.length) break;
  }
  return windows;
}

export function buildMessages(path: string, totalLines: number, w: Window): ChatMessage[] {
  const width = String(w.end).length;
  const numbered = w.lines.map((l, i) => `${String(w.start + i).padStart(width)}| ${l}`).join('\n');
  const range = w.start === 1 && w.end === totalLines ? '' : ` (lines ${w.start}-${w.end} of ${totalLines})`;
  const candidates =
    w.candidates.length === 0
      ? 'Candidates: none.'
      : `Candidates:\n${w.candidates.map((c) => `- ${c.id} (line ${c.line}, ${c.kind}${c.value ? `, ${c.value}` : ''}): ${c.text}`).join('\n')}`;
  return [
    { role: 'system', content: SYSTEM },
    { role: 'user', content: `File: ${path}${range}\n\n${numbered}\n\n${candidates}` },
  ];
}

export function retryMessages(messages: ChatMessage[], answer: string, error: string): ChatMessage[] {
  return [
    ...messages,
    { role: 'assistant', content: answer },
    { role: 'user', content: `That answer is invalid: ${error}\nAnswer again with JSON only, matching the schema.` },
  ];
}
