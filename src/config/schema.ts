import { z } from 'zod';

// Schema of csp.yml. It is the single source for validation and for the
// published csp.schema.json (see scripts/emit-schema.ts).
// csp.yml holds human decisions only; machine findings live in csp.lock.

export const DIRECTIVES = [
  'default-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'style-src',
  'style-src-elem',
  'style-src-attr',
  'img-src',
  'font-src',
  'connect-src',
  'media-src',
  'object-src',
  'frame-src',
  'child-src',
  'worker-src',
  'manifest-src',
  'frame-ancestors',
  'base-uri',
  'form-action',
  'upgrade-insecure-requests',
  'sandbox',
  'report-uri',
  'report-to',
  'trusted-types',
  'require-trusted-types-for',
] as const;

export type Directive = (typeof DIRECTIVES)[number];

export const PRIORITIES = ['low', 'medium', 'high'] as const;
export type Priority = (typeof PRIORITIES)[number];

const SourceObject = z
  .strictObject({
    value: z.string().min(1).describe('CSP source, e.g. self, https://js.stripe.com, unsafe-inline'),
    status: z
      .enum(['pending', 'accepted'])
      .optional()
      .describe('pending: found by the tool, nobody decided yet. accepted: risk accepted (requires reason)'),
    reason: z
      .string()
      .min(1)
      .optional()
      .describe('Why this source is needed. A reason accepts the source unless status is pending'),
    dev_only: z.boolean().optional().describe('Only included in dev environments'),
  })
  .refine((s) => s.status !== 'accepted' || s.reason !== undefined, {
    message: 'status "accepted" requires a reason',
    path: ['reason'],
  });

const Source = z.union([z.string().min(1), SourceObject]);

const Directives = z.partialRecord(z.enum(DIRECTIVES), z.array(Source));

const DocumentSchema = z.strictObject({
  routes: z.array(z.string().min(1)).min(1).describe('Routes served by this document'),
  mode: z
    .enum(['report-only', 'enforce'])
    .default('report-only')
    .describe('report-only: Content-Security-Policy-Report-Only. enforce: Content-Security-Policy'),
  directives: Directives.prefault({}),
});

const SettingsSchema = z.strictObject({
  fail_on: z
    .enum(['none', ...PRIORITIES])
    .default('none')
    .describe('`check` fails on unresolved warnings at or above this priority'),
  require_reason: z
    .enum(PRIORITIES)
    .default('medium')
    .describe('Warnings at or above this priority need an accepted status with a reason'),
  dev_environments: z
    .array(z.string().min(1))
    .default(['dev'])
    .describe('Environments where dev_only sources are included'),
  report: z
    .strictObject({
      endpoint: z.url().describe('Where browsers send violation reports'),
      group: z.string().min(1).default('csp-endpoint'),
    })
    .optional(),
});

export const ConfigSchema = z.strictObject({
  $schema: z.string().optional(),
  version: z.literal(1),
  settings: SettingsSchema.prefault({}),
  variables: z
    .record(
      z.string().regex(/^[A-Z_][A-Z0-9_]*$/, 'variable names are UPPER_SNAKE_CASE'),
      z.record(z.string().min(1), z.string().min(1)),
    )
    .default({})
    .describe('Per-environment values, referenced as ${NAME}'),
  common: Directives.prefault({}).describe('Directives added to every document'),
  documents: z
    .record(z.string().regex(/^[a-z0-9][a-z0-9_-]*$/, 'document names are lowercase'), DocumentSchema)
    .refine((docs) => Object.keys(docs).length > 0, 'at least one document is required'),
});

export type Config = z.output<typeof ConfigSchema>;
export type DocumentConfig = Config['documents'][string];
export type SourceEntry = z.output<typeof Source>;
export type DirectivesConfig = z.output<typeof Directives>;
