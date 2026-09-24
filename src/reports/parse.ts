// Parses CSP violation reports as browsers send them. Two formats:
// - report-uri (CSP2): {"csp-report": {"document-uri", "effective-directive", "blocked-uri", ...}}
// - Reporting API (report-to): [{"type": "csp-violation", "body": {"documentURL", "effectiveDirective", "blockedURL", ...}}]
// A file may hold one report, an array, POST bodies collected as arrays, or one JSON value per line (NDJSON).

export interface Violation {
  documentUrl: string;
  /** Directive that was violated, e.g. script-src-elem. */
  directive: string;
  /** URL of the blocked resource, or a keyword such as "inline" or "eval". */
  blocked: string;
  sourceFile?: string;
  disposition?: string;
}

export interface ParseResult {
  violations: Violation[];
  /** Entries that are not CSP violation reports (other Reporting API types, garbage). */
  skipped: number;
}

export class ReportFormatError extends Error {}

export function parseReports(text: string): ParseResult {
  const result: ParseResult = { violations: [], skipped: 0 };
  for (const value of parseJsonValues(text)) collect(value, result);
  return result;
}

function parseJsonValues(text: string): unknown[] {
  const trimmed = text.trim();
  if (trimmed === '') return [];
  try {
    return [JSON.parse(trimmed)];
  } catch {
    // Not a single JSON value: try NDJSON.
  }
  return trimmed
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, i) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        throw new ReportFormatError(`line ${i + 1} is not valid JSON`);
      }
    });
}

function collect(value: unknown, result: ParseResult): void {
  if (Array.isArray(value)) {
    for (const item of value) collect(item, result);
    return;
  }
  const violation = toViolation(value);
  if (violation) result.violations.push(violation);
  else result.skipped++;
}

function toViolation(value: unknown): Violation | undefined {
  if (!isObject(value)) return undefined;

  const legacy = value['csp-report'];
  if (isObject(legacy)) {
    const directive = str(legacy['effective-directive']) ?? firstToken(str(legacy['violated-directive']));
    const documentUrl = str(legacy['document-uri']);
    if (!directive || !documentUrl) return undefined;
    return {
      documentUrl,
      directive,
      blocked: str(legacy['blocked-uri']) ?? '',
      sourceFile: str(legacy['source-file']),
      disposition: str(legacy['disposition']),
    };
  }

  if (value['type'] === 'csp-violation' && isObject(value['body'])) {
    const body = value['body'];
    const directive = str(body['effectiveDirective']);
    const documentUrl = str(body['documentURL']) ?? str(value['url']);
    if (!directive || !documentUrl) return undefined;
    return {
      documentUrl,
      directive,
      blocked: str(body['blockedURL']) ?? '',
      sourceFile: str(body['sourceFile']),
      disposition: str(body['disposition']),
    };
  }
  return undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function firstToken(value: string | undefined): string | undefined {
  return value?.trim().split(/\s+/)[0];
}
