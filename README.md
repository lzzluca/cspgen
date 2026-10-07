# cspgen

[![CI](https://github.com/lzzluca/cspgen/actions/workflows/ci.yml/badge.svg)](https://github.com/lzzluca/cspgen/actions/workflows/ci.yml)

Review, version and roll out the **Content Security Policy** of a web app.

A CSP is one of the strongest defenses against XSS, and one of the easiest to get wrong: it is either so permissive that it protects nothing (`'unsafe-inline'`, `https:`), or so strict that it breaks the app on the first deploy. `cspgen` treats the policy as code: a reviewed YAML file with one policy per document, a reason for every risky source, a CI gate, and a safe path from `report-only` to enforcement.

> **Status: early, work in progress.** Reviewing policies, managing them as code and importing browser violation reports work today. `cspgen analyze` (experimental) asks an LLM what the code loads, checks every answer against the cited file and line, and records the result in `csp.lock`; turning that into a policy (`cspgen generate`) is the next milestone, see [Roadmap](#roadmap).

## Install

Requires Node.js 22.12 or later. Not yet published to npm:

```sh
git clone https://github.com/lzzluca/cspgen.git
cd cspgen
npm ci && npm run build
npm link        # makes `cspgen` available on your PATH
```

## Review any site's CSP

No configuration needed. `cspgen` fetches the page, reads the policy from the headers (and any `<meta>` tag), and rates every weakness against the strictest possible CSP:

```sh
cspgen review --url https://example.com
cspgen review --header "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src *"
```

```
Document enforced  mode: enforce
  Warnings:
    HIGH   script-src 'unsafe-inline' (needs reason)
           'unsafe-inline' allows any inline script, including injected ones: use nonces
    HIGH   object-src (needs reason)
           object-src (falls back to default-src) allows plugins (<object>, <embed>) that can run code; set object-src 'none'
    HIGH   base-uri (needs reason)
           base-uri is not set: an injected <base> tag can redirect relative script URLs; set base-uri 'none' or 'self'
    MEDIUM script-src https://cdn.jsdelivr.net (needs reason)
           scripts from https://cdn.jsdelivr.net run with full access: CDNs and JSONP endpoints can be used to bypass the policy
    MEDIUM style-src 'unsafe-inline' (needs reason)
           'unsafe-inline' in styles allows CSS injection (data exfiltration, UI redressing)
    LOW    script-src 'self'
           'self' allows any script served by your origin, including uploaded files or JSONP endpoints
    LOW    img-src *
           * allows any host for img-src

Summary: 3 high, 2 medium, 2 low
⚠ 3 unresolved HIGH-priority warnings: this policy leaves significant XSS risk open.
```

The rules are deterministic, inspired by Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/), and aware of how browsers actually behave: fallbacks to `default-src`, `'unsafe-inline'` being ignored next to a nonce, host allowlists being ignored under `'strict-dynamic'`.

| Priority | Examples |
|---|---|
| **High** | `'unsafe-inline'` or `'unsafe-eval'` in `script-src`; `*`, `https:` or `data:` in `script-src`; missing `object-src` or `base-uri` |
| **Medium** | `'unsafe-inline'` in `style-src`; `'unsafe-hashes'`; third-party script hosts; `localhost` sources shipped outside dev |
| **Low** | `'self'` in `script-src`; third-party hosts for images, fonts, connections; wildcards outside scripts |

## Manage the policy as code

The policy lives in `csp.yml`, next to your code. It describes **documents** rather than routes, because a CSP applies to a document load: in a SPA (or within a Phoenix LiveView `live_session`) many routes share one document, and therefore one policy.

```yaml
# yaml-language-server: $schema=./csp.schema.json
version: 1

variables:
  API_HOST:
    dev: localhost:4000
    prod: api.example.com

common:                       # added to every document
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
    mode: report-only         # being rolled out
    directives:
      script-src:
        - self
        - value: https://cdn.tiny.cloud
          status: pending     # found, nobody decided yet
```

- **Every risky source needs a reason.** Medium and high warnings stay open until someone writes down why the source is needed; the reason is reviewed in the PR like any other change.
- **One policy for all environments**, with variables for hosts and `dev_only` for development-only sources, so "tested in dev" means "works in prod".
- **Keywords with or without quotes** (`self` or `"'self'"`), and a [JSON Schema](csp.schema.json) for completion and validation in your editor.

`cspgen review` turns the file into ready-to-paste headers for every document and environment, with the warnings that are still open:

```
Document learning  mode: enforce  /, /learning/*
  [prod]
    Content-Security-Policy: default-src 'none'; object-src 'none'; base-uri 'none'; ... script-src 'self' 'unsafe-inline'; connect-src 'self' wss://api.example.com
  Warnings:
    HIGH   script-src 'unsafe-inline' (accepted)
           'unsafe-inline' allows any inline script, including injected ones: use nonces
           reason: inline userId in the layout, moving to nonces in SEC-123
```

Edit the file by hand, or with commands that show a diff and keep your comments and formatting intact:

```sh
cspgen accept https://cdn.tiny.cloud --reason "TinyMCE editor in the admin pages"
cspgen add-source https://js.stripe.com -d script-src -D learning --reason "Stripe Elements in the course checkout"
cspgen promote admin          # report-only → enforce, after listing what is still undecided
```

### In CI

```sh
cspgen check --fail-on high
```

Fails on unresolved warnings at or above the threshold. The default (`fail_on: none` in `csp.yml`) only reports, so the tool never blocks a team that has not opted in.

## Roll out with real traffic

The safe way to introduce or tighten a CSP is to ship it as `Content-Security-Policy-Report-Only` first, collect what browsers would have blocked, then enforce it. On a busy site that means thousands of reports; `import-reports` turns them into a short, reviewable patch:

```sh
cspgen import-reports reports.ndjson --min-count 5
```

```
Read 1,134 CSP violation report(s) (1 other entries skipped).
  ignored 360 caused by browser extensions or the browser itself
  25 on pages no document route matches: /login (25)

Sources missing from the policy (most frequent first):
      180×  learning  img-src https://i.ytimg.com  e.g. https://i.ytimg.com/vi/abc/hq.jpg
       95×  learning  frame-src https://www.youtube-nocookie.com  e.g. https://www.youtube-nocookie.com/embed/xyz
        2×  admin  connect-src https://weird-tracker.example.net  (below --min-count, not proposed)

3 reported source(s) are already allowed (reports from an older policy or cached pages).

--- csp.yml
+++ csp.yml
@@ -36,6 +36,12 @@
+      img-src:
+        - value: https://i.ytimg.com
+          status: pending
+      frame-src:
+        - value: https://www.youtube-nocookie.com
+          status: pending
```

It reads both report formats browsers send (`report-uri` and the Reporting API's `report-to`), as JSON or NDJSON. Nothing is written until you pass `--write`, which also records the observations in `csp.observations.yml`. Try it with the sample in [`examples/phoenix/`](examples/phoenix).

## Roadmap

- **Generate the policy from the source code.** `cspgen analyze` already finds the sources in the code with an LLM (local models via Ollama, or any OpenAI-compatible API), checks every claim against a cited file and line, and caches the results in a committed `csp.lock`. `cspgen check` warns when the lock is out of date. Still to come: `cspgen generate` (the `csp.yml` patch) and detecting routes and document boundaries.
- **Nonce migration patches** for the detected stack, proposed as diffs, never applied automatically.
- **Runtime verification with Playwright**, reusing the app's E2E suite to confirm sources and compute hashes from the real HTML.
- Drift check between `csp.yml` and the headers actually served; Sentry import; SARIF output for GitHub code scanning.

The reasoning behind these choices is in [DECISIONS.md](DECISIONS.md).

## Development

```sh
npm test           # vitest
npm run typecheck
npm run build
npm run schema     # regenerate csp.schema.json after changing src/config/schema.ts
```

## License

[MIT](LICENSE)
