import { writeFile } from 'node:fs/promises';
import { z } from 'zod';
import { ConfigSchema } from '../src/config/schema.js';

// Emits csp.schema.json from the zod schema, for editor completion and validation.
const schema = z.toJSONSchema(ConfigSchema, { io: 'input', unrepresentable: 'any' });
await writeFile(
  new URL('../csp.schema.json', import.meta.url),
  `${JSON.stringify({ ...schema, title: 'cspgen configuration (csp.yml)' }, null, 2)}\n`,
);
