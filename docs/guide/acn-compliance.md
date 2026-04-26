# Allineamento ACN e D.Lgs 138/2024

Questa pagina documenta come la piattaforma si allinea al quadro normativo italiano per la NIS2, incluse le Determine ACN e le scadenze operative.

## Quadro normativo di riferimento

| Norma | Descrizione | Stato piattaforma |
|-------|-------------|-------------------|
| **D.Lgs 138/2024** | Recepimento italiano della Direttiva NIS2 (EU 2022/2555) | Supportato |
| **Determina ACN 127434/2026** | Misure di sicurezza di base (scadenza luglio 2027) | Supportato |
| **Determina ACN 127437/2026** | Elencazione fornitori rilevanti (Art. 18) | Roadmap |
| **Modello BIA ACN** | Business Impact Analysis standardizzata (di prossima pubblicazione) | Roadmap |

## Mappatura Art. 21 D.Lgs 138/2024

La checklist governance della piattaforma copre tutte le 10 sottosezioni dell'Art. 21 con 30 item pesati:

| Sottosezione Art. 21 | Ambito | Checklist item |
|----------------------|--------|----------------|
| (a) Politiche di analisi dei rischi | Risk assessment, metodologia, aggiornamento periodico | 3 item |
| (b) Gestione degli incidenti | Detection, response, notifica CSIRT, lessons learned | 3 item |
| (c) Continuita' operativa | BCP, DRP, backup, test periodici | 3 item |
| (d) Sicurezza della catena di approvvigionamento | Vendor assessment, contratti, monitoraggio fornitori | 3 item |
| (e) Sicurezza nell'acquisizione e sviluppo | SDLC sicuro, code review, vulnerability management | 3 item |
| (f) Valutazione dell'efficacia delle misure | Audit interni, KPI sicurezza, penetration testing | 3 item |
| (g) Pratiche di igiene informatica e formazione | Awareness, phishing simulation, competenze team | 3 item |
| (h) Crittografia | Policy crittografica, key management, algoritmi | 3 item |
| (i) Sicurezza delle risorse umane | Onboarding/offboarding, screening, accesso privilegiato | 3 item |
| (j) Autenticazione e controllo accessi | MFA, RBAC, PAM, SSO, log accessi | 3 item |

## Determina 127434/2026 — Misure di sicurezza di base

La Determina 127434 definisce le misure di sicurezza di base che i soggetti NIS2 devono implementare **entro luglio 2027**.

La piattaforma supporta la verifica automatizzata continua delle seguenti misure tecniche:

| Categoria misura | Controlli automatizzati |
|-----------------|------------------------|
| Configurazione sicura dei servizi esposti | TLS version, cipher suite, HSTS, CSP, X-Frame-Options |
| Gestione dei certificati | Chain validation, OCSP, CT logs, key strength, expiry monitoring |
| Sicurezza DNS | DNSSEC, SPF, DMARC, DKIM, zone transfer protection |
| Controllo accessi di rete | Port exposure analysis (14 porte critiche), SSH hardening |
| Monitoraggio e rilevamento | secrets exposure, version disclosure, WAF/CDN detection |
| Protezione dei dati in transito | TLS enforcement, weak protocol probing, certificate pinning |

### Scadenze operative

| Scadenza | Requisito |
|----------|-----------|
| **Luglio 2027** | Implementazione misure di sicurezza di base |
| **Continuativo** | Verifica periodica dell'efficacia delle misure |

## Determina 127437/2026 — Fornitori rilevanti (Art. 18)

La Determina 127437 richiede l'elencazione dei fornitori rilevanti per la sicurezza della catena di approvvigionamento.

### Stato attuale: Roadmap

Il modulo Vendor Risk Management e' in fase di sviluppo e includera':

- Censimento fornitori con classificazione per criticita'
- Valutazione rischio per singolo fornitore
- Import CSV per integrazione con registri esistenti
- Tracciamento contrattuale (clausole di sicurezza, SLA, audit rights)
- Dashboard con distribuzione del rischio supply chain
- Export per template ACN

### Workaround attuale

La checklist governance include 3 item dedicati alla sottosezione (d) dell'Art. 21, che coprono:
- Esistenza di una politica di gestione fornitori
- Processo di valutazione iniziale dei fornitori
- Monitoraggio continuo e revisione periodica

## Business Impact Analysis (BIA)

ACN ha annunciato la pubblicazione di un modello standardizzato per la BIA. La piattaforma si predispone all'integrazione:

### Integrazione pianificata

- Import del template BIA ACN alla pubblicazione ufficiale
- Collegamento automatico tra BIA e asset registrati nella piattaforma
- Calcolo dell'impatto basato sui dati di scansione e compliance
- Export nei formati richiesti da ACN

## Incident Reporting — Art. 23 CSIRT

La piattaforma supporta la raccolta strutturata delle informazioni necessarie per le notifiche CSIRT Italia:

| Fase notifica | Tempistica | Supporto piattaforma |
|---------------|-----------|---------------------|
| Early Warning | Entro 24 ore | Template strutturato con campi pre-compilati |
| Incident Notification | Entro 72 ore | Raccolta evidenze, timeline, tassonomia EU |
| Final Report | Entro 1 mese | Aggregazione dati, IOC, impatto, lezioni apprese |

La piattaforma genera report strutturati compatibili con i requisiti informativi della piattaforma ACN, semplificando la raccolta delle evidenze necessarie per la notifica nei tempi previsti.

> **Nota:** La piattaforma non si interfaccia direttamente con il portale ACN. Genera i dati strutturati che il responsabile della notifica inserira' manualmente o tramite i canali ufficiali previsti da ACN.

## Separazione NIS2 e GDPR

La piattaforma distingue chiaramente tra controlli NIS2 e controlli GDPR/ePrivacy:

| Ambito | Controlli | Normativa |
|--------|-----------|-----------|
| **NIS2 / D.Lgs 138/2024** | TLS, DNS security, port exposure, certificate health, incident reporting, governance checklist | Direttiva (EU) 2022/2555 |
| **EU Privacy / GDPR Posture** | P.IVA, privacy policy, cookie banner | GDPR, ePrivacy, Codice del Consumo |

I due ambiti sono separati nell'interfaccia e nei report per evitare confusione normativa.

## Nota sulla piattaforma

Questo strumento e' progettato come **ponte open-source** per facilitare la compliance NIS2. Non si sostituisce ai portali e ai template ufficiali ACN, ma agevola la raccolta, la verifica e l'esportazione dei dati necessari per l'adempimento normativo.

Per supporto nell'implementazione o per una licenza commerciale: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)
