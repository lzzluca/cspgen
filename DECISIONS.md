# CSP Generator — Decisioni di design

Registro delle decisioni prese durante la fase di design (sessioni di "grilling", settembre 2026).
Per ogni decisione: cosa, e perché.

---

## 1. Obiettivo e modalità

CLI che genera, revisiona e controlla in CI la Content Security Policy di una webapp.
Tre modalità, costruite sugli stessi componenti:

1. **Genera**: dal codice produce una CSP per documento, la più stretta possibile *senza rompere l'app*, più un report dei warnings.
2. **Revisiona**: valuta una CSP esistente (dallo YAML del tool o dagli header serviti) contro il riferimento strict.
3. **CI**: stesso comando, stesso comportamento, dentro e fuori dalla CI. Nella prima versione il controllo in CI è solo statico ("questa PR introduce nuove sorgenti o nuovi inline?").

**Utenti:** sviluppatori e devops.

**Strategia (prima funziona, poi migliora):** prima una policy che non rompe niente, poi un report che spiega come renderla più stretta.
*Perché:* una CSP piena di `'unsafe-inline'` dà una falsa sicurezza, ma una CSP strict imposta subito impedisce di adottarla. Il valore del tool sta nel colmare questa distanza.

## 2. Riferimento e warnings

- Il riferimento è la **CSP più strict possibile**. Ogni aggiunta è un warning, con una priorità in base al rischio (scala ispirata alle regole del CSP Evaluator di Google):

  | Priorità | Esempi |
  |---|---|
  | **Alta** | `unsafe-inline` o `unsafe-eval` in `script-src`. `*`, `https:` o `data:` in `script-src`. `object-src` o `base-uri` mancanti. |
  | **Media** | `unsafe-inline` in `style-src`. `unsafe-hashes`. Host di terze parti in `script-src`. |
  | **Bassa** | `self` in `script-src`. Host di terze parti in `img-src`, `font-src` o `connect-src`. |
  | **Nessuna** | `none`, `nonce`, hash, `strict-dynamic`, direttive dei report, `upgrade-insecure-requests`. |

- Warnings e priorità sono calcolati da **codice deterministico**, mai dall'LLM: stessa policy, stessi warnings.
- **Motivazione obbligatoria** solo per le priorità **media e alta** (soglia configurabile). Quelle basse sono solo informative.
  *Perché:* se bisognasse motivare anche `self` o un'immagine da un CDN, i warnings diventerebbero rumore.
- Un warning si **accetta con una motivazione**: basta scrivere `reason` sulla sorgente (a mano, oppure con `cspgen accept <valore> --reason "..."`). **Una motivazione equivale ad "accettato"**, a meno che la sorgente sia marcata `status: pending`; `status: accepted` esplicito resta valido. La motivazione viene committata e rivista nella PR.
  *Perché:* meno campi da scrivere a mano; `pending` resta l'unico stato che il tool scrive.
- **CI:** soglia configurabile da chi usa il tool (`fail_on`). **Default `fail_on: none`**: la CI non fallisce mai, ma il report mostra chiaramente i warnings ad alta priorità ancora aperti.
  *Perché:* il tool non deve bloccare deploy o PR senza una scelta esplicita del team.

## 3. Il file `csp.yml` (fonte di verità)

- Il tool ha un suo formato YAML, che è la **fonte di verità**. La configurazione servita (nginx, plug, middleware) viene ricavata da lì e non va modificata a mano.
- Il file sta nella root del repository (`--config` per spostarlo).
- **Contiene solo decisioni umane:** valore, stato (`pending` / `accepted`), motivazione, `dev_only`, modalità di rollout. I fatti trovati dalla macchina (prove, provenienza, osservazioni) stanno nel lock e nelle osservazioni.
  *Perché:* chi modifica cosa è chiaro, e lo YAML cambia solo quando cambia una decisione. Niente diff rumorosi né conflitti di merge causati dal tool.
- **Il tool non riscrive mai lo YAML**, propone patch:
  - le sorgenti nuove entrano come `pending`
  - quelle non più necessarie vengono segnalate come da rimuovere
  - quelle già motivate non vengono toccate
- Si può modificare **sia a mano sia con i comandi**, ed è **sempre validato**. Il tool pubblica `csp.schema.json` (JSON Schema) per la validazione e il completamento automatico negli editor.
- **Deriva:** se l'header servito non corrisponde allo YAML, warning in locale e fallimento in CI.

### Schema
- **La chiave principale è il documento**, con la sua lista di route.
  - Il **nome** lo propone il tool: l'LLM lo ricava dalla struttura del codice (nome della `live_session` o della pipeline, layout), altrimenti dal prefisso delle route (`/admin/*` → `admin`). Si può rinominare a mano.
  - L'**identità** di un documento dipende dalle sue **route**, non dal nome: dopo una rinomina il tool lo ritrova. Se una route passa a un altro documento, lo propone come patch.
- **Forma breve:** un valore è una stringa quando non servono metadati, un oggetto (`value`, `status`, `reason`, `dev_only`) quando servono.
- **Parole chiave con o senza apici** (`self` oppure `"'self'"`). Il tool scrive la forma senza apici e li aggiunge nell'header. Non c'è ambiguità: le parole chiave CSP sono un elenco chiuso.
- **Blocco `common:`** sommato a ogni documento. Un solo livello, niente `extends`.
- **`pending`** vuol dire "c'è nella policy, e aspetta che qualcuno decida":
  - la sorgente è **inclusa** nella policy generata (prima non rompere)
  - genera un warning se la sua priorità richiede una motivazione
  - fa fallire la CI solo se `fail_on` lo richiede

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
          status: accepted
          reason: "userId inline nel layout, migrazione ai nonce in SEC-123"
      connect-src:
        - self
        - "wss://${API_HOST}"
        - value: "ws://localhost:4000"
          dev_only: true
          reason: "live reload di Phoenix"

  admin:
    routes: ["/admin/*"]
    mode: report-only
    directives:
      script-src:
        - self
        - value: https://cdn.tiny.cloud
          status: pending
```

Nomi precisi dei campi e dettagli dello schema da rifinire quando si scrive il codice.

### Ambienti
Una sola policy, con **variabili per gli host** (`${API_HOST}`) e il **flag `dev_only`** sulla singola sorgente. Niente ereditarietà né sovrascritture per ambiente.
L'ambiente si sceglie con `--env` o `CSPGEN_ENV` (il flag vince). Senza nessuno dei due si generano gli header per **tutti** gli ambienti.
*Perché:* così "testata in dev" vuol dire "funziona in prod", e le motivazioni non vengono duplicate. Il tool avvisa se una sorgente `dev_only` finisce in prod.

### Rollout
Ogni documento ha una modalità `report-only` oppure `enforce`. Durante la fase `report-only`, l'eventuale policy precedente **resta in vigore** (due header in parallelo), quindi la produzione non è mai meno protetta di prima. Il passaggio si fa con un comando esplicito (`cspgen promote`). `promote` **avvisa** se per quel documento ci sono osservazioni non ancora rivedute.

## 4. Documenti, non route

- L'unità della CSP è il **documento**: la CSP si applica al caricamento di un documento, non a una navigazione lato client.
  - SPA: molte route condividono un documento, e quindi una policy.
  - SSR / MPA: una route corrisponde a un documento.
  - Phoenix LiveView: le route nella stessa `live_session` condividono il documento. Passando a un'altra `live_session`, o a un'altra pipeline, la pagina si ricarica e la CSP può cambiare.
- Il tool riconosce da solo quali route condividono un documento.
- Il report spiega che pagine della **stessa origin** non sono isolate tra loro: la CSP per documento riduce la superficie d'attacco, ma non isola le pagine.

## 5. Analisi: LLM + codice deterministico

**L'LLM capisce, il codice controlla e produce.** Il supporto a qualsiasi stack è possibile solo grazie all'LLM.

| Codice deterministico | LLM |
|---|---|
| Elenco dei file, hash, gestione del lock | Route e confini dei documenti |
| URL letterali nel codice, come *candidati* | URL costruiti a runtime |
| Verifica delle citazioni (la riga esiste e contiene quello che l'LLM dice?) | Provenienza (sorgente ↔ dipendenza) |
| Calcolo di warnings e priorità | Snippet di configurazione per lo stack |
| Validazione dello YAML, generazione degli header, controllo della deriva | Patch per i nonce, nome proposto per i documenti |

- **Ogni affermazione dell'LLM cita file e riga**, e la citazione viene verificata. Se la citazione manca o non torna, l'affermazione è segnalata come "non verificata".
- Domande piccole e mirate, con risposte in JSON, così da funzionare anche con modelli locali.
- **Provenienza:**
  - "sconosciuta" (con priorità più alta) per le sorgenti senza una causa nel codice, come quello che inietta GTM
  - "da rimuovere" per le sorgenti la cui dipendenza è sparita
- **Sorgenti trovate solo nel codice**, mai viste a runtime: **restano nella policy**, marcate `solo statica`.
  *Perché:* toglierle romperebbe proprio le pagine che nessun test visita.

### Provider LLM e privacy
- L'utente fornisce la propria chiave API. Il provider è configurabile: cloud, Bedrock o Vertex, locale (Ollama...).
- All'avvio un **banner informativo** dice dove va il codice. Il modello locale è consigliato, ma la scelta è dell'utente.
- `--dry-run` mostra esattamente cosa verrebbe inviato all'LLM.

### `csp.lock`
- **YAML**, scritto solo dal tool, con chiavi ordinate (diff puliti), **committato**. Sta nella root, accanto a `csp.yml`.
- È una **cache dell'analisi del codice**: si ricostruisce interamente dal codice.
- **`files`:** per ogni file, l'hash del contenuto e i findings. Ogni finding contiene `kind` (`external-source`, `inline-script`, `inline-style`, `inline-handler`, `eval`), sorgente, direttiva, prova (riga e testo), provenienza e `verified`.
- **`documents`:** le conclusioni che dipendono da più file (route, confini dei documenti). La chiave è l'insieme degli hash elencati in `depends_on`.
- In testa al file stanno modello e versione del prompt.
- In locale si rianalizzano solo i file cambiati. In CI si esegue lo stesso comando:
  - lock aggiornato: nessuna chiamata all'LLM, risultato deterministico e veloce
  - lock non aggiornato: warning ("lancia `cspgen analyze`")
- Il diff del lock nella PR mostra a chi fa la review cosa ha concluso l'LLM.

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
        provenance: "TinyMCE, editor nelle pagine admin"
        verified: true

documents:
  admin:
    depends_on:
      lib/app_web/router.ex: sha256:91ac...
    routes: ["/admin/*"]
    evidence: { file: lib/app_web/router.ex, line: 52, text: "live_session :admin" }
```

## 6. Osservazioni e report dalla produzione

- Un'**osservazione** è un fatto visto nel browser: "sul documento X, la CSP avrebbe bloccato la risorsa Y". Prova che una sorgente serve davvero.
- Le osservazioni stanno in **`csp.observations.yml`**, separato dal lock.
  *Perché:* il lock si ricostruisce dal codice, le osservazioni vengono dall'app in esecuzione e non sono ricostruibili.
- Campi principali: documento, direttiva, risorsa bloccata, `source` (`production-report`, in futuro `playwright`), `env`, data, `count`.
- **Nella prima versione le osservazioni arrivano da `cspgen import-reports <file.json>`**, un file esportato da Sentry o report-uri, o raccolto dal vostro endpoint. Il tool:
  - raggruppa i duplicati (`count`)
  - scarta il rumore noto (estensioni del browser, `about:`, script iniettati dal browser)
  - propone una patch con le sorgenti nuove come `pending`, ordinate per frequenza
  - segna come `vista a runtime` le sorgenti già presenti

  *Perché:* su un'app molto usata i report sono migliaia, e rivederli a mano uno per uno non è sostenibile. L'import chiude il ciclo del rollout: report-only, import, revisione, promote.
- Per un singolo caso visto a mano in DevTools basta `cspgen add-source ... --reason "..."`.

## 7. Script e stili inline

- La policy generata **funziona subito**:
  - **nella prima versione niente hash:** gli script inline si autorizzano con `unsafe-inline` e un warning **alto**
  - `unsafe-hashes` per gli handler `onclick`

  *Perché niente hash:* l'hash deve corrispondere byte per byte allo script *servito*, mentre il tool legge il *template*, e il motore di template può cambiare spazi e a capo. Un hash calcolato dal sorgente rischia di rompere l'app. Gli hash arriveranno con Playwright, quando il tool vedrà l'HTML reale.
- Ogni direttiva ad alto rischio è **chiaramente evidenziata** nel report.
- Nel report testuale i warnings **bassi** dello stesso tipo sulla stessa direttiva (per esempio 14 host esterni in `connect-src`) vengono **raggruppati** in una riga; `--verbose` li elenca tutti.
- L'LLM propone, per lo stack rilevato, la **patch per usare i nonce** (+ `strict-dynamic`) come diff da rivedere. **Mai applicata in automatico.**
- **Nonce:** nello YAML si scrive `nonce`. L'header generato contiene un segnaposto (`'nonce-{NONCE}'`), e lo snippet per lo stack spiega come riempirlo a ogni richiesta.

## 8. Output

- **Report:** testo a terminale, ed esportazione JSON a richiesta.
- **Configurazione:** header generici pronti da incollare (uno per documento), più uno snippet per lo stack generato dall'LLM. Lo snippet è controllato dal confronto tra header servito e YAML.
- **Consegna:** solo header HTTP. Il tool non genera `<meta>`, ma segnala quelli esistenti nella review.
- **Report delle violazioni:** il tool chiede se attivarli e dove inviarli, poi aggiunge `report-uri` + `report-to` / `Reporting-Endpoints`.

## 9. Comandi della CLI (di massima)

| Comando | Cosa fa |
|---|---|
| `cspgen init` | Primo avvio: rileva lo stack, sceglie il provider LLM (con il banner), crea `csp.yml` |
| `cspgen analyze` | Aggiorna `csp.lock`, analizzando solo i file cambiati |
| `cspgen generate` | Propone la patch allo YAML, stampa gli header e lo snippet per lo stack |
| `cspgen review` | Valuta lo YAML oppure gli header di un URL, e stampa il report |
| `cspgen check` | Il comando per la CI: lock aggiornato, deriva, warnings rispetto a `fail_on` |
| `cspgen accept` | Accetta un warning con una motivazione |
| `cspgen add-source` | Aggiunge una sorgente a mano, con motivazione |
| `cspgen import-reports` | Importa i report delle violazioni da un file JSON |
| `cspgen promote` | Passa un documento da `report-only` a `enforce` |

Nomi e opzioni precise da definire scrivendo il codice.

**Modifiche a `csp.yml`:** i comandi che modificano il file mostrano sempre il diff. Quelli lanciati esplicitamente da una persona (`accept`, `add-source`, `promote`) lo applicano subito, con `--dry-run` per vederlo soltanto. Una modifica che renderebbe il file non valido viene rifiutata. Il tool scrive le parole chiave senza apici e conserva commenti, ordine e formattazione del resto del file.

**Stato (settembre 2026):** fatti `review` (da `csp.yml`, `--url`, `--header`), `check`, `accept`, `add-source`, `promote`. Mancano `init`, `analyze`, `generate`, `import-reports`, il lock e il controllo di deriva.

## 10. Tecnologia

- CLI in **TypeScript** (Playwright, tree-sitter e i client degli LLM sono disponibili nell'ecosistema). Il linguaggio del tool non limita il linguaggio delle app analizzate.

---

## Prossimi passi (fuori dalla prima versione, in ordine di priorità)

1. **Verifica a runtime con Playwright: da fare per prima, appena il tool si può provare.**
   - La policy candidata viene aggiunta come `Report-Only` intercettando le risposte, senza modificare l'app.
   - Riuso della suite E2E se esiste, altrimenti un crawler con login.
   - Report di copertura (route trovate nel codice / visitate / mai visitate).
   - Le violazioni diventano osservazioni con `source: playwright`: il formato è già pronto.
   - **Hash per gli inline statici**, calcolati dall'HTML reale servito al browser.
   - "Vista a runtime" vale per *una sorgente*, mai per la policy intera: non vedere una violazione non prova che la policy sia completa.
   - Nella prima versione si testa a mano: il tool stampa l'header `Report-Only` e le istruzioni ("le violazioni compaiono nella console di DevTools").
2. Integrazioni dirette con le API di Sentry e report-uri, per importare i report senza passare da un file.
3. Report in Markdown per i commenti nelle PR, e in SARIF per le annotazioni di GitHub.
4. Patch dello YAML consegnate come PR (history in git).

## Note

- Quando ci sarà il primo codice: aggiungere `AGENTS.md` / `CLAUDE.md` con i comandi di build e test, e un rimando a questo file.
