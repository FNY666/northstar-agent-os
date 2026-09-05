# Northstar Agent OS

**Componenti runtime aperti, affidabili e governati per colleghi IA autonomi.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**In una frase:** Northstar è un progetto indipendente per comporre colleghi IA governati usando routing esplicito dei modelli, limiti agli strumenti locali, auditabilità ed esecuzione recuperabile. **Il componente pubblicato oggi è Northstar Codex Sidecar, un adattatore locale limitato per worker — non una piattaforma completa di agenti autonomi.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Che cos’è

Northstar è un progetto runtime orientato ai componenti per sviluppatori che vogliono far operare i colleghi IA entro limiti visibili, invece di affidarsi a un ciclo senza vincoli di prompt e strumenti. Si concentra su blocchi piccoli e verificabili: un contratto visibile al chiamante, esecuzione limitata, risultati strutturati e recupero operativo.

Il progetto viene costruito in modo incrementale. Un componente può essere utile da solo, ma il superamento dei test non dimostra che una piattaforma completa di agenti sia sicura o pronta per la produzione.

## Cosa viene pubblicato oggi

- `../components/northstar-codex-sidecar/` — servizio locale Unix socket che valida le richieste, esegue Codex in modalità read-only, limita input e output, redige gli errori, pulisce i gruppi di processi scaduti e restituisce stati strutturati.
- Test deterministici, modello di hardening systemd, installer prudente e script di rollback.

## Come funziona il Sidecar

Viene accettata una richiesta JSON per ogni connessione Unix socket:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

La risposta è un oggetto JSON delimitato:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Proprietà importanti:

- Solo Unix socket; nessun listener TCP.
- Allowlist rigorosa: `request_id`, `prompt`, `timeout_ms`.
- Limiti per prompt e timeout.
- Codex viene eseguito con `--sandbox read-only` e `--ephemeral`.
- Gruppo di processi separato, pulito con TERM e poi KILL al timeout.
- Scadenza di lettura per connessione e pool di worker limitato.
- Classi di errore strutturate e redazione dei segreti.
- Utente di servizio dedicato e modello di hardening systemd.
- Codex resta disabilitato finché un amministratore non installa e abilita esplicitamente il servizio.

## Avvio rapido

Requisiti: Linux, Python 3.10 o superiore, un eseguibile `codex` installato separatamente e disponibile all’utente del servizio, systemd e un utente/workspace dedicato senza privilegi.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Esamina gli script e l’account di servizio prima di abilitare il ciclo prudente:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

L’eseguibile Codex viene risolto da `PATH`; imposta `CODEX_BIN` per un percorso non standard.

## A chi è rivolto

Northstar è per sviluppatori e operatori di runtime IA locali o self-hosted che necessitano di un componente di esecuzione limitato, testabile, auditabile, disattivabile e ripristinabile. Non è un prodotto IA ospitato, una garanzia di sicurezza automatica né un sostituto di un’architettura completa per identità, policy, workspace e osservabilità.

## Cosa non è

- Non è ancora un sistema operativo multi-agente completo.
- Non è un servizio ospitato né una promessa di prontezza per la produzione.
- Non è un’API generica per l’esecuzione della shell.
- Non autorizza da solo i chiamanti, non isola ogni esecuzione e non propaga l’annullamento del processo padre.
- Non include credenziali Codex né fornisce un account Codex.

**Not a complete autonomous-agent platform.**

## Rapporto con OpenBot

Northstar è un progetto indipendente destinato a integrazioni compatibili con OpenBot. Non è affiliato né approvato da OpenBot, CopilotKit o dai loro manutentori. Il Sidecar può integrarsi con runtime in stile OpenBot senza affermare di far parte del repository upstream OpenBot.

La compatibilità indica un obiettivo di integrazione, non proprietà, approvazione o equivalenza di sicurezza.

## Confine di sicurezza

Il Sidecar autentica i chiamanti solo tramite permessi Unix. Un’integrazione di produzione deve inoltre fornire autorizzazione e binding dell’identità del chiamante, isolamento del workspace per run o actor, propagazione della cancellazione, osservabilità senza registrare prompt sensibili, health check e rollback, verifica di concorrenza e albero dei processi su Linux nativo e revisione dell’account, rete e configurazione degli strumenti Codex.

Non esporre il Unix socket tramite un proxy TCP. Non eseguire mai il commit di API key, token OAuth, stato di login Codex, chiavi private, file `.env` di produzione o trascrizioni degli utenti.

## Stato del progetto

Questo è il primo componente pubblico di Northstar. Il runtime più ampio di Northstar Agent OS viene costruito incrementando gradualmente. Identity binding, autorizzazione del workspace per run, propagazione della cancellazione, verifica end-to-end su Linux nativo e integrazione del deployment in produzione restano responsabilità dell’host o lavori futuri. **Questo repository non è una piattaforma completa di agenti autonomi.**

La pulizia dei gruppi di processi deve essere validata sulla distribuzione Linux nativa di destinazione; il comportamento di segnali e recupero PID su Linux mobile potrebbe non essere rappresentativo.

## Contributi e manutenzione

Consulta [CONTRIBUTING.md](../CONTRIBUTING.md) per aspettative su prove, test, sicurezza, compatibilità e rollback. Consulta [SECURITY.md](../SECURITY.md) per le segnalazioni di sicurezza. English is the canonical source for project scope; translations should be updated when it changes.

## Licenza

MIT. Vedi [LICENSE](../LICENSE).
