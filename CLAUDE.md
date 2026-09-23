# cspgen

CLI in TypeScript che genera, revisiona e controlla la CSP di una webapp.
**Prima di cambiare l'architettura o il formato dei file, leggi `DECISIONS.md`.**

## Comandi

- `npm test`: test (vitest)
- `npm run typecheck`
- `npm run build`: compila in `dist/`
- `npm run schema`: rigenera `csp.schema.json` da `src/config/schema.ts` (va fatto dopo ogni modifica allo schema)
- `npm run dev -- review -c examples/phoenix/csp.yml`: esegue la CLI senza build

## Struttura

- `src/config/`: schema zod di `csp.yml` (unica fonte, anche per il JSON Schema), parsing con numeri di riga, controlli semantici
- `src/policy/`: valori CSP (parole chiave con o senza apici), risoluzione di una policy per documento + ambiente, generazione e parsing degli header
- `src/rules/evaluate.ts`: warnings e priorità. Solo codice deterministico, mai LLM.
- `src/report/`: report (review per `csp.yml` o per una CSP live) e output testuale
- `examples/phoenix/csp.yml`: esempio di riferimento, usato anche dai test

## Convenzioni

- ESM, import con estensione `.js`
- Messaggi della CLI in inglese
