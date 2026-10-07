# cspgen — Design decisions

Record of the decisions taken during the design phase (September 2026).
For each decision: what, and why.

---

## 1. Goal and modes

A CLI that generates, reviews and checks in CI the Content Security Policy of a web app.
Three modes, built on the same components:

1. **Generate**: from the code, produce one CSP per document, as strict as possible *without breaking the app*, plus a report of warnings.
2. **Review**: evaluate an existing CSP (from the tool's YAML or from the served headers) against the strictest reference.
3. **CI**: same command, same behavior, inside and outside CI. In the first version the CI check is static only ("does this PR introduce new sources or new inline code?").

**Users:** developers and DevOps engineers.

**Strategy (first make it work, then make it strict):** first a policy that breaks nothing, then a report that explains how to tighten it.
*Why:* a CSP full of `'unsafe-inline'` gives a false sense of security, but imposing a strict CSP right away prevents adoption. The value of the tool is in closing that gap.

## 2. Reference and warnings

- The reference is the **strictest possible CSP**. Every addition is a warning, with a priority based on risk (scale inspired by the rules of Google's CSP Evaluator):

  | Priority | Examples |
  |---|---|
  | **High** | `unsafe-inline` or `unsafe-eval` in `script-src`. `*`, `https:` or `data:` in `script-src`. Missing `object-src` or `base-uri`. No `script-src` at all. |
  | **Medium** | `unsafe-inline` in `style-src`. `unsafe-hashes`. Third-party hosts in `script-src`. Development sources (localhost) outside dev environments. |
  | **Low** | `self` in `script-src`. Third-party hosts in `img-src`, `font-src`, `connect-src`, etc. Wildcards outside scripts. `unsafe-inline` next to a nonce or hash (ignored by modern browsers). |
  | **None** | `none`, `nonce`, hashes, `strict-dynamic`, reporting directives, `upgrade-insecure-requests`. With `strict-dynamic`, host allowlists and `self` in `script-src` are not flagged, since CSP3 browsers ignore them. |

- Warnings and priorities are computed by **deterministic code**, never by the LLM: same policy, same warnings.
- **A reason is required** only for **medium and high** priorities (threshold configurable). Low ones are informational.
  *Why:* if `self` or an image CDN needed a justification, warnings would become noise.
- A warning is **accepted by giving a reason**: write `reason` on the source (by hand, or with `cspgen accept <value> --reason "..."`). **A reason means "accepted"** unless the source is marked `status: pending`; an explicit `status: accepted` is still valid. The reason is committed and reviewed in the PR.
  *Why:* fewer fields to write by hand; `pending` is the only status the tool writes.
- **CI:** threshold configurable by the team (`fail_on`). **Default `fail_on: none`**: CI never fails, but the report clearly shows the unresolved high-priority warnings.
  *Why:* the tool must not block deploys or PRs without an explicit choice by the team.

## 3. The `csp.yml` file (source of truth)

- The tool has its own YAML format, which is the **source of truth**. The served configuration (nginx, plug, middleware) is derived from it and must not be edited by hand.
- The file lives at the repository root (`--config` to move it).
- **It holds human decisions only:** value, status (`pending` / `accepted`), reason, `dev_only`, rollout mode. Facts found by the machine (evidence, provenance, observations) live in the lock and in the observations file.
  *Why:* it is clear who edits what, and the YAML changes only when a decision changes. No noisy diffs or merge conflicts caused by the tool.
- **The tool never rewrites the YAML**, it proposes patches:
  - new sources come in as `pending`
  - sources no longer needed are flagged for removal
  - sources that already have a reason are left alone
- It can be edited **both by hand and through commands**, and is **always validated**. The tool publishes `csp.schema.json` (JSON Schema) for validation and completion in editors.
- **Drift:** if the served header does not match the YAML, a warning locally and a failure in CI.

### Schema
- **The top-level key is the document**, with its list of routes.
  - The **name** is proposed by the tool: the LLM derives it from the code structure (name of the `live_session` or pipeline, layout), otherwise from the route prefix (`/admin/*` → `admin`). It can be renamed by hand.
  - A document's **identity** is its **routes**, not its name: after a rename the tool still finds it. If a route moves to another document, the tool proposes it as a patch.
- **Short form:** a value is a string when it needs no metadata, an object (`value`, `status`, `reason`, `dev_only`) when it does.
- **Keywords with or without quotes** (`self` or `"'self'"`). The tool writes the unquoted form and adds quotes in the header. There is no ambiguity: CSP keywords are a closed list.
- **A `common:` block** added to every document. One level only, no `extends`.
- **`pending`** means "it is in the policy, waiting for someone to decide":
  - the source is **included** in the generated policy (first, don't break)
  - it produces a warning if its priority requires a reason
  - it fails CI only if `fail_on` says so

```yaml
version: 1

settings:
  fail_on: none
  report:
    endpoint: https://o123.ingest.sentry.io/api/456/security/?sentry_key=...

variables:
  API_HOST:
    dev: localhost:4000
    staging: api.staging.example.com
    prod: api.example.com

common:
  default-src: [none]
  object-src: [none]
  base-uri: [none]

documents:
  learning:
    routes: ["/", "/learning/*"]
    mode: enforce
    directives:
      script-src:
        - self
        - value: unsafe-inline
          reason: "inline userId in the layout, moving to nonces in SEC-123"
      connect-src:
        - self
        - "wss://${API_HOST}"
        - value: "ws://localhost:4000"
          dev_only: true
          reason: "Phoenix live reload"

  admin:
    routes: ["/admin/*"]
    mode: report-only
    directives:
      script-src:
        - self
        - value: https://cdn.tiny.cloud
          status: pending
```

### Environments
A single policy, with **variables for hosts** (`${API_HOST}`) and a **`dev_only` flag** on individual sources. No inheritance or per-environment overrides.
The environment is chosen with `--env` or `CSPGEN_ENV` (the flag wins). With neither, headers are generated for **all** environments. `settings.dev_environments` (default `["dev"]`) lists the environments where `dev_only` sources are included.
*Why:* "tested in dev" then means "works in prod", and reasons are not duplicated. The tool warns when a development source (localhost) reaches another environment without `dev_only`.

### Rollout
Each document has a mode, `report-only` or `enforce`. During the `report-only` phase any previous policy **stays in force** (two headers side by side), so production is never less protected than before. Switching is an explicit command (`cspgen promote`), which first lists the warnings still needing a reason and the `pending` sources.

## 4. Documents, not routes

- The unit of a CSP is the **document**: a CSP applies when a document loads, not to client-side navigation.
  - SPA: many routes share one document, and therefore one policy.
  - SSR / MPA: one route is one document.
  - Phoenix LiveView: routes in the same `live_session` share the document. Moving to another `live_session`, or another pipeline, reloads the page and the CSP can change.
- The tool works out which routes share a document. *(Deferred: for now documents are written by hand, see §5 "What is analyzed".)*
- The report explains that pages of the **same origin** are not isolated from each other: a per-document CSP reduces the attack surface, but does not isolate pages.

## 5. Analysis: LLM + deterministic code

**The LLM understands, the code checks and produces.** Supporting any stack is only possible thanks to the LLM.

| Deterministic code | LLM |
|---|---|
| File listing, hashes, lock management | Routes and document boundaries |
| Literal URLs in the code, as *candidates* | URLs built at runtime |
| Citation checks (does the line exist and contain what the LLM claims?) | Provenance (source ↔ dependency) |
| Warnings and priorities | Configuration snippet for the stack |
| YAML validation, header generation, drift check | Nonce patch, proposed document names |

- **Every LLM claim cites a file and line**, and the citation is checked. A missing or wrong citation marks the claim as "unverified".
- Small, targeted questions with JSON answers, so that local models work too.
- **Provenance:**
  - "unknown" (with higher priority) for sources with no cause in the code, such as what GTM injects
  - "to remove" for sources whose dependency is gone
- **Sources found only in the code**, never seen at runtime, **stay in the policy**, marked `static only`.
  *Why:* removing them would break exactly the pages no test visits.

### What is analyzed
- **File selection is deterministic.** Candidates are the files tracked by git (so `.env` and anything in `.gitignore` never leave the machine), minus dependency and build folders (`node_modules`, `deps`, `_build`, `dist`...) and `analysis.exclude`. Of these, the tool sends frontend and template files (`.html`, `.heex`, `.erb`, `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.css`...) and any other file where a candidate pattern matches (see below).
  *Known limit:* the selection will miss something. The `report-only` rollout and `import-reports` are the safety net.
- **One question per file**: "find everything relevant to the CSP", with numbered lines. Long files are split into overlapping windows. It matches the lock, which is per file.
- **Documents are not detected yet.** The documents are the ones written in `csp.yml`, and `generate` applies the findings to every document: in practice one policy for the whole app, which is exact for a SPA. Detecting document boundaries from the router (for example Phoenix `live_session`) is deferred.

### Checking the LLM
The LLM proposes, deterministic code checks, and what fails a check stays visible: it never disappears silently and it is never accepted automatically.
- **Answers are validated** against a zod schema. An invalid answer is retried once with the validation error in the prompt; a second failure marks the file as `error` in the lock.
- **Citations are checked with string comparisons**, no second LLM: each finding carries `line` and `text`. The finding is `verified` if `text` (whitespace-normalized) is on the cited line or near it (the line number is then corrected), and `text` contains the source. Otherwise it is `unverified`.
  The check proves the thing **exists in the code**, not that it **matters for the CSP** (a URL called by the server, not by the browser, is in the code but not in the policy). Relevance stays a judgment of the LLM, visible in the lock diff and reviewed as a `pending` source.
- **Cross-check with candidate patterns.** A few regexes (literal URLs, `<script`, `<link`, `<iframe`, `<style`, quoted `style=` and `on...=` attributes, `fetch(` / `new WebSocket(` / `new EventSource(` / `new Worker(`, `eval(` / `new Function`) find the obvious candidates. For each one, the LLM must return a verdict: relevant (it becomes a finding) or not relevant, with a reason (an SVG namespace, a URL used server-side). A candidate the LLM ignores becomes a finding marked `missed_by_llm`. The regexes are not meant to be complete: finding what they cannot see (URLs built at runtime) is the LLM's job.
- **`unverified` findings are not in the `generate` patch.** They are listed in the report, for the reader to look at.
- **The LLM never writes a `reason`.** It only fills `provenance`, which is informational: a reason is a person's decision.
- **The LLM never judges risk:** priorities come from the deterministic rules only.

### LLM provider and privacy
- **One protocol: the OpenAI-compatible chat API**, with a small client built on `fetch` and no SDK. It covers local servers (Ollama, LM Studio, vLLM), OpenRouter (Claude, GPT, DeepSeek and others with one key) and OpenAI. Native Bedrock and Vertex are not supported (they are reachable through OpenRouter).
- **Configuration in `csp.yml`**, the same for the whole team so that the lock does not change between developers: `analysis: { base_url, model, reasoning_effort, exclude }`. `reasoning_effort` is sent only when set: `none` turns thinking off on Ollama, about 8 times faster with gemma4 (144 s → 17 s on a 15-line file). Answers are streamed, so that slow local models do not hit HTTP timeouts. The API key comes only from an environment variable (`CSPGEN_API_KEY`). `--model` overrides locally, with a warning when it does not match the lock.
- On startup, an **informational banner** says where the code goes. Local models are recommended, but the choice is the user's.
- `--dry-run` shows exactly what would be sent to the LLM.

### Testing
- **The tool's code** (citation checks, cross-check, lock, cache invalidation) is tested with hand-written LLM answers, with no model. These tests run in CI.
- **The quality of the analysis** is tried by hand on a real app: writing-app, the author's own project (not public), a Vite + React SPA with a Fastify API,, with a local model (`gemma4` on Ollama). Expected: `script-src 'self'`; `connect-src 'self'` (API calls go through the same-origin proxy); the Vite websocket and inline styles as `dev_only`; the LLM hosts called by the API (DeepSeek, Ollama) **not** in the policy.

### `csp.lock`
- **YAML**, written only by the tool, with sorted keys (clean diffs), **committed**. It lives at the root, next to `csp.yml`.
- It is a **cache of the code analysis**: it can be rebuilt entirely from the code.
- **`files`:** for each file, the content hash and the findings. Each finding has a `kind` (`external-source`, `inline-script`, `inline-style`, `inline-handler`, `eval`), source, directive, evidence (line and text), provenance and `verified`. Findings for candidates the LLM ignored are marked `missed_by_llm`; candidates it judged not relevant are kept with its reason, so the lock diff shows them too.
- **`documents`:** conclusions that depend on several files (routes, document boundaries). The key is the set of hashes listed in `depends_on`.
- The model and prompt version are at the top of the file.
- Locally, only changed files are analyzed again. CI runs the same command:
  - lock up to date: no LLM call, deterministic and fast
  - lock stale: warning ("run `cspgen analyze`")
- The lock diff in the PR shows reviewers what the LLM concluded.

```yaml
version: 1
model: ollama/qwen2.5-coder:14b
prompt_version: 3

files:
  lib/app_web/live/admin_live.ex:
    hash: sha256:44b0e7...
    findings:
      - kind: external-source
        source: https://cdn.tiny.cloud
        directive: script-src
        evidence: { line: 88, text: '<script src="https://cdn.tiny.cloud/...">' }
        provenance: "TinyMCE, editor in the admin pages"
        verified: true

documents:
  admin:
    depends_on:
      lib/app_web/router.ex: sha256:91ac...
    routes: ["/admin/*"]
    evidence: { file: lib/app_web/router.ex, line: 52, text: "live_session :admin" }
```

## 6. Observations and production reports

- An **observation** is a fact seen in a browser: "on document X, the CSP would have blocked resource Y". It proves a source is really needed.
- Observations live in **`csp.observations.yml`**, separate from the lock.
  *Why:* the lock can be rebuilt from the code; observations come from the running app and cannot.
- Fields: `document`, `directive`, `source` (the CSP source), `count`, `examples` (a few blocked URLs), `from` (`production-report`, later `playwright`), `env` (when known), `last_seen`. The field is called `from`, not `source`, to avoid confusion with the CSP source.
- **In the first version observations come from `cspgen import-reports <file...>`.** Supported formats: `report-uri` (`{"csp-report": ...}`) and the Reporting API (`report-to`), as a single JSON value, an array or NDJSON (one report per line). Sentry exports come later. The tool:
  - groups duplicates by document, directive and source (`count`), reducing URLs to their origin (`https://cdn.tiny.cloud/1/x.js` → `https://cdn.tiny.cloud`), same-origin URLs to `self`, and `inline` / `eval` to `unsafe-inline` / `unsafe-eval`
  - maps each report to a document through its routes (the most specific pattern wins) and lists the paths no document covers
  - drops known noise (browser extensions, `about:`)
  - flags sources that are already allowed (reports from an older policy or cached pages)
  - proposes a patch with the new sources as `pending`, most frequent first; `--min-count` drops those seen too rarely
  - when a new directive used to fall back to `default-src`, copies the `default-src` values first, so adding it never narrows the policy by accident

  *Why:* on a busy app there are thousands of reports, and reviewing them one by one is not sustainable. Importing closes the rollout loop: report-only, import, review, promote.
- Being a machine proposal, **it only shows the patch by default**: `--write` applies it and records the observations.
- Known limitation: importing the same file twice adds its counts again.
- For a single case seen by hand in DevTools, `cspgen add-source ... --reason "..."` is enough.

## 7. Inline scripts and styles

- The generated policy **works right away**:
  - **no hashes in the first version:** inline scripts are allowed with `unsafe-inline` and a **high** warning
  - `unsafe-hashes` for `onclick` handlers

  *Why no hashes:* a hash must match the *served* script byte for byte, while the tool reads the *template*, and the template engine can change whitespace and line breaks. A hash computed from the source could break the app. Hashes will come with Playwright, when the tool sees the real HTML.
- Every high-risk directive is **clearly highlighted** in the report.
- In the text report, **low** warnings of the same kind on the same directive (for example 14 external hosts in `connect-src`) are **grouped** on one line; `--verbose` lists them all.
- For the detected stack, the LLM proposes a **patch to use nonces** (+ `strict-dynamic`) as a diff to review. **Never applied automatically.**
- **Nonces:** in the YAML, write `nonce`. The generated header contains a placeholder (`'nonce-{NONCE}'`), and the stack snippet explains how to fill it on every request.

## 8. Output

- **Report:** terminal text, and JSON export on request.
- **Configuration:** generic headers ready to paste (one per document), plus a stack snippet generated by the LLM. The snippet is checked by comparing the served header with the YAML.
- **Delivery:** HTTP headers only. The tool does not generate `<meta>` tags, but flags existing ones in reviews.
- **Violation reports:** the tool asks whether to enable them and where to send them, then adds `report-uri` + `report-to` / `Reporting-Endpoints`.

## 9. CLI commands

| Command | What it does |
|---|---|
| `cspgen init` | First run: detects the stack, picks the LLM provider (with the banner), creates `csp.yml` |
| `cspgen analyze` | Updates `csp.lock`, analyzing only changed files |
| `cspgen generate` | Proposes the YAML patch, prints the headers and the stack snippet |
| `cspgen review` | Evaluates the YAML, a live URL or a header value, and prints the report |
| `cspgen check` | The CI command: lock up to date, drift, warnings against `fail_on` |
| `cspgen accept` | Accepts a source by giving its reason |
| `cspgen add-source` | Adds a source by hand, optionally with a reason |
| `cspgen import-reports` | Imports violation reports and proposes the missing sources |
| `cspgen promote` | Switches a document from `report-only` to `enforce` |

**Editing `csp.yml`:** commands that change the file always show the diff. Commands a person runs explicitly (`accept`, `add-source`, `promote`) apply it right away, with `--dry-run` to only show it. Commands that propose changes found by the machine (`import-reports`, later `generate`) only show the diff, and apply it with `--write`. An edit that would make the file invalid is refused. The tool writes keywords without quotes and preserves comments, order and formatting of the rest of the file.

**Status (September 2026):** done: `review` (from `csp.yml`, `--url`, `--header`), `check`, `accept`, `add-source`, `promote`, `import-reports`, `analyze` and the lock (findings per file; documents not detected yet), the stale-lock warning in `check`. Missing: `init`, `generate`, the drift check.

## 10. Technology

- **TypeScript** CLI (Playwright, tree-sitter and LLM clients are all available in the ecosystem). The tool's language does not limit the language of the apps it analyzes.

---

## Next steps (after the first version, by priority)

1. **Runtime verification with Playwright: first, as soon as the tool can be tried.**
   - The candidate policy is added as `Report-Only` by intercepting responses, without changing the app.
   - Reuse the E2E suite if there is one, otherwise a crawler with login.
   - Coverage report (routes found in the code / visited / never visited).
   - Violations become observations with `from: playwright`: the format is ready.
   - **Hashes for static inline scripts**, computed from the real HTML served to the browser.
   - "Seen at runtime" applies to *a source*, never to the whole policy: not seeing a violation does not prove the policy is complete.
   - Until then, testing is manual: the tool prints the `Report-Only` header and instructions ("violations show up in the DevTools console").
2. **Automatic document detection** from the router and layouts (Phoenix `live_session` and pipelines, SSR routes), with document names proposed by the LLM.
3. Import from Sentry exports, and direct integrations with the Sentry and report-uri APIs.
4. Markdown reports for PR comments, and SARIF for GitHub annotations.
5. YAML patches delivered as PRs (history in git).
