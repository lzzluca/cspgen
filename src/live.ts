import type { LiveCsp } from './report/review.js';

/** Reads the CSP a live page actually serves: headers plus any <meta http-equiv> tag. */
export async function fetchLiveCsp(url: string): Promise<LiveCsp> {
  const response = await fetch(url, { redirect: 'follow' });
  const enforced = response.headers.get('content-security-policy');
  const reportOnly = response.headers.get('content-security-policy-report-only');
  const contentType = response.headers.get('content-type') ?? '';
  const html = contentType.includes('html') ? await response.text() : '';
  return {
    enforced: enforced ? [enforced] : [],
    reportOnly: reportOnly ? [reportOnly] : [],
    meta: extractMetaCsp(html),
  };
}

export function extractMetaCsp(html: string): string[] {
  const policies: string[] = [];
  for (const [tag] of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(tag)) continue;
    const content = /content\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    const value = content?.[1] ?? content?.[2];
    if (value) policies.push(decodeEntities(value));
  }
  return policies;
}

function decodeEntities(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, '&');
}
