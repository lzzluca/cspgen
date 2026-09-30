# cspgen

TypeScript CLI that generates, reviews and checks the CSP of a web app.
**Read `DECISIONS.md` before changing the architecture or any file format.**

## Commands

- `npm test`: tests (vitest)
- `npm run typecheck`
- `npm run build`: compiles to `dist/`
- `npm run schema`: regenerates `csp.schema.json` from `src/config/schema.ts` (run it after every schema change)
- `npm run dev -- review -c examples/phoenix/csp.yml`: runs the CLI without building

## Layout

- `src/config/`: zod schema of `csp.yml` (single source, also for the JSON Schema), parsing with line numbers, semantic checks
- `src/config/edit.ts`: edits to `csp.yml` that preserve comments and formatting; every command that writes the file goes through it
- `src/policy/`: CSP values (keywords with or without quotes), resolving a policy per document + environment, generating and parsing headers
- `src/policy/routes.ts`: route patterns (`/`, `/products/:id`, `/admin/*`)
- `src/rules/evaluate.ts`: warnings and priorities. Deterministic code only, never an LLM.
- `src/report/`: reports (review of `csp.yml` or of a live CSP) and text output
- `src/reports/`: import of browser violation reports (format parsing, grouping, noise filtering)
- `src/analyze/`: `cspgen analyze` and `csp.lock`: file selection (git-tracked only), candidate regexes, prompt and answer schema, OpenAI-compatible client, citation checks. The LLM only proposes; every answer is checked by code here
- `src/observations.ts`: `csp.observations.yml`, written only by the tool
- `examples/phoenix/`: reference `csp.yml` (also used by tests) and `reports.ndjson`, sample reports for `import-reports`

## Conventions

- ESM, imports with the `.js` extension
- CLI messages in English
