# Matrice di Conformità NIS2

La piattaforma copre tutti e dieci i sotto-paragrafi (da a a j) dell'Art. 21 NIS2, il ciclo di vita della notifica degli incidenti dell'Art. 23 e i requisiti della supply chain dell'Art. 18.

**Legenda**:
- **Implementato** — completamente automatizzato, nessun passaggio manuale richiesto lato piattaforma
- **Parziale** — i controlli automatici coprono la superficie tecnicamente osservabile; i controlli organizzativi richiedono verifica umana nella checklist di governance
- **Manuale** — la direttiva richiede esplicitamente giudizio umano; l'automazione non può sostituirlo

---

## Art. 21 — Misure di Gestione del Rischio

| Sotto-paragrafo | Perimetro | Stato | Implementazione nella piattaforma |
|---|---|---|---|
| (a) Politiche di analisi del rischio e sicurezza delle informazioni | Metodologia, aggiornamenti periodici, registro rischi | Parziale | Checklist di governance + `POST /governance/sync-risk` scala le voci della checklist quando sono aperti finding HIGH/CRITICAL; `GET /governance/risk-summary` restituisce il riepilogo rischi per articolo |
| (b) Gestione degli incidenti | Rilevamento, risposta, contenimento, notifica CSIRT | Implementato | Modulo incidenti con ciclo di vita Art. 23; Celery Beat verifica ogni 15 min e invia alert alle soglie 24h/72h/1 mese con deduplicazione Redis |
| (c) Continuità operativa | BCP, DRP, politica backup, test periodici | Implementato (verifica manuale) | Modulo BIA — RTO/RPO/MTPD per processo, scoring impatto (finanziario, operativo, reputazionale, regolatorio, sicurezza), mappatura dipendenze, rilevamento gap |
| (d) Sicurezza della supply chain | Valutazione fornitori, contratti, diritti di audit | Implementato | Modulo Vendor Risk con formula di scoring 0–100 documentata (certificazioni, accesso ai dati, recenza audit, localizzazione geografica, clausole di sicurezza); formula accessibile agli auditor a `GET /vendors/score-formula`; flag rilevanza ACN Art. 18 |
| (e) Acquisizione, sviluppo e manutenzione sicuri | SDLC, gestione vulnerabilità, revisione codice | Parziale | Engine di validazione tecnica (TLS, header HTTP, port scanning, rilevamento segreti) + checklist di governance per i controlli SDLC organizzativi |
| (f) Valutazione dell'efficacia | Audit interni, KPI, penetration testing | Parziale | Confronto scansioni per analisi dei trend, punteggio di conformità nel tempo; checklist per i requisiti di audit formale |
| (g) Igiene informatica e formazione | Programmi di sensibilizzazione, simulazione phishing | Manuale | Checklist di governance — verifica umana richiesta per design della direttiva |
| (h) Crittografia e gestione delle chiavi | Politica crittografica, ciclo di vita chiavi, TLS | Parziale | Controlli automatici: versione TLS, cipher suite, scadenza certificato, fiducia catena, presenza HSTS; checklist per la politica di gestione delle chiavi |
| (i) Sicurezza delle risorse umane | Onboarding, offboarding, revisioni accesso, screening | Manuale | Checklist di governance — verifica umana richiesta per design della direttiva |
| (j) Autenticazione e controllo degli accessi | MFA, RBAC, PAM, log degli accessi | Implementato | TOTP MFA per utente; accesso basato su ruoli (admin/auditor/viewer); chiavi API con scope per endpoint tramite `dual_auth_with_scope`; log di audit completo; JWT RS256 con endpoint JWKS; integrità sessione tramite rotazione refresh token |

---

## Art. 23 — Notifica degli Incidenti (CSIRT)

| Fase | Scadenza legale | Supporto piattaforma |
|---|---|---|
| Early Warning | 24 ore dal rilevamento | `POST /incidents/{id}/early-warning` genera un JSON pronto per il CSIRT; alert automatico alla scadenza e 2 ore prima |
| Notifica Incidente | 72 ore dal rilevamento | Modulo di notifica strutturato con tassonomia UE, IOC e timeline; stessa logica di alert |
| Rapporto Finale | 1 mese dal rilevamento | Valutazione dell'impatto aggregato e lessons learned; stessa logica di alert |

Gli alert vengono inviati tramite canali di notifica (email, webhook con firma HMAC-SHA256, Slack). **La trasmissione a CSIRT Italia** (`csirt.gov.it`) è un passaggio manuale — la piattaforma produce gli elaborati ma non invia direttamente al portale CSIRT.

---

## Art. 18 — Sicurezza della Supply Chain

| Funzionalità | Stato |
|---|---|
| Inventario fornitori con classificazione criticità (1–4) | Implementato |
| Scoring sicurezza 0–100 con formula documentata | Implementato |
| Tracciamento campi contrattuali (SLA, diritti audit, clausole sicurezza) | Implementato |
| Localizzazione geografica e livello di accesso ai dati | Implementato |
| Tracciamento certificazioni (ISO 27001, SOC 2, CSA STAR) | Implementato |
| Recenza dell'audit come fattore di scoring | Implementato |
| Flag rilevanza ACN Art. 18 (Italia) | Implementato |
| Export JSON compatibile ACN | Implementato (schema preliminare — in attesa del template ufficiale ACN) |

---

## Trasposizione Nazionale — Italia (D.Lgs 138/2024)

| Riferimento | Copertura |
|---|---|
| D.Lgs 138/2024 | Riferimenti Art. 21 nella checklist di governance |
| Determina ACN 127434/2026 | Riferimenti baseline tecnica nella matrice di conformità |
| Determina ACN 127437/2026 | Inventario fornitori con campi specifici ACN |
| Scadenze conformità ACN | Conto alla rovescia in tempo reale: referente CSIRT (dic 2026), obbligo notifica 24h (gen 2027), misure baseline (lug 2027) |
| Export compatibile ACN | `GET /acn-export/art18` (inventario fornitori), `GET /acn-export/bia` (BIA) |

Lo schema di export ACN è preliminare. Il *modello di categorizzazione* ufficiale annunciato da ACN non è stato pubblicato alla data della v2.5.11. L'export attuale è una mappatura strutturale best-effort basata sulla Determina 127437/2026 e verrà aggiornata una volta disponibile il template ufficiale.

---

## Cosa la Piattaforma Non Sostituisce

La piattaforma non sostituisce:
- Un CISO o un professionista qualificato della sicurezza
- Un programma di audit interno o un penetration test formale
- La revisione legale dei propri specifici obblighi ai sensi del D.Lgs 138/2024 e della classificazione dell'ente
- Il rapporto diretto con ACN per la registrazione e le comunicazioni formali di conformità
- Le decisioni di governance a livello di CDA e l'allocazione del budget per la sicurezza

La checklist di governance traccia le voci che richiedono questi processi umani. La matrice di conformità e i finding dello scanner informano tali processi ma non li sostituiscono.
