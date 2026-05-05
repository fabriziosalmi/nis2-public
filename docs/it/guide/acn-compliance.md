# Italia: D.Lgs 138/2024 e ACN

Questa pagina documenta il modulo di recepimento nazionale italiano. La Direttiva NIS2 (UE 2022/2555) è recepita in Italia tramite il D.Lgs 138/2024. L'autorità nazionale competente è l'ACN (Agenzia per la Cybersicurezza Nazionale).

## Quadro normativo

| Riferimento | Descrizione | Stato piattaforma |
|-----------|-------------|----------------|
| **D.Lgs 138/2024** | Recepimento italiano NIS2 | Supportato |
| **Determina ACN 127434/2026** | Misure di sicurezza tecniche di base (scadenza: luglio 2027) | Supportato |
| **Determina ACN 127437/2026** | Inventario fornitori rilevanti (Art. 18) | Implementato (schema preliminare — in attesa del *modello di categorizzazione* ufficiale ACN, previsto per maggio/giugno 2026) |
| **Template BIA ACN** | Business Impact Analysis standardizzata | Modello interno presente; l'allineamento al modello ufficiale ACN avverrà dopo la sua pubblicazione |

## Mappatura Art. 21 (D.Lgs 138/2024)

La checklist di governance fa riferimento esplicitamente a tutti e 10 i sotto-paragrafi (a)-(j) dell'Art. 21 tramite un enum `subparagraph`. Ogni elemento porta il suo tag e l'API espone `/governance/by-subparagraph` per reportistica raggruppata. Diversi sotto-paragrafi sono fondamentalmente non automatizzabili (es. responsabilità del CdA, formazione, sicurezza HR) e vengono tracciati come *verifica manuale richiesta* nella checklist.

| Sotto-paragrafo Art. 21 | Ambito | Elementi |
|--------------------|-------|-------|
| (a) Policy di analisi dei rischi | Metodologia di risk assessment, aggiornamenti periodici | 3 |
| (b) Gestione incidenti | Rilevamento, risposta, notifica CSIRT, lesson learned | 3 |
| (c) Continuità aziendale | BCP, DRP, backup, test periodici | 3 |
| (d) Sicurezza della supply chain | Valutazione fornitori, contratti, monitoraggio fornitori | 3 |
| (e) Acquisizione e sviluppo sicuri | SDLC sicuro, code review, vulnerability management | 3 |
| (f) Valutazione di efficacia | Audit interni, KPI di sicurezza, penetration testing | 3 |
| (g) Igiene informatica e formazione | Awareness, simulazioni phishing, competenze team | 3 |
| (h) Crittografia | Policy crypto, gestione chiavi, algoritmi | 3 |
| (i) Sicurezza delle risorse umane | Onboarding/offboarding, screening, accessi privilegiati | 3 |
| (j) Autenticazione e controllo accessi | MFA, RBAC, PAM, SSO, log degli accessi | 3 |

## Determina 127434/2026 -- Misure di sicurezza di base

La Determina 127434 definisce le misure di sicurezza di base che i soggetti NIS2 devono implementare **entro luglio 2027**.

La piattaforma offre una verifica automatizzata e continua delle seguenti misure tecniche:

| Categoria misura | Controlli automatizzati |
|-----------------|-----------------|
| Configurazione sicura servizi | Versione TLS, cipher suite, HSTS, CSP, X-Frame-Options |
| Gestione certificati | Validazione catena, OCSP, CT log, forza chiave, monitoraggio scadenze |
| Sicurezza DNS | DNSSEC, SPF, DMARC, DKIM, protezione da zone transfer |
| Controllo accessi rete | Analisi esposizione porte (14 porte critiche), hardening SSH |
| Monitoraggio e rilevamento | Esposizione segreti, version disclosure, rilevamento WAF/CDN |
| Protezione dati in transito | Enforcing TLS, probing protocolli deboli, certificate pinning |

### Scadenze operative (D.Lgs 138/2024 + Determine ACN)

| Scadenza | Requisito |
|----------|------------|
| **31 Dicembre 2026** | Designazione del referente CSIRT per comunicazioni e incident reporting (Art. 23) |
| **1 Gennaio 2027** | Inizio obbligo notifica Early Warning entro 24 ore (Art. 23) |
| **Luglio 2027** | Implementazione misure di sicurezza di base (Determina 127434) |
| **Luglio 2027** | Completamento inventario fornitori + BIA + Risk Assessment |
| **Continuo** | Verifica periodica dell'efficacia |

La piattaforma espone `GET /api/v1/deadlines` con timer in tempo reale e flag di urgenza per ciascuna di queste date.

## Determina 127437/2026 -- Fornitori rilevanti (Art. 18)

La Determina 127437 richiede l'inventario dei fornitori rilevanti per la sicurezza della supply chain.

### Stato: Implementato (schema di esportazione preliminare)

Il modulo Vendor Risk Management è attivo con le seguenti funzionalità:

- Inventario fornitori con classificazione criticità (1-4)
- Punteggio di valutazione sicurezza (0-100)
- Tracciamento contratti (SLA, diritti di audit, clausole di sicurezza)
- Posizione geografica e livello di accesso ai dati
- Tracciamento certificazioni (ISO 27001, SOC2, CSA STAR)
- Flag rilevanza Art. 18 ACN
- Esportazione JSON compatibile ACN: `GET /api/v1/acn-export/art18`

> **Stato dello schema: preliminare.** La risposta esportata presenta il tag `"schema_version": "1.0-preliminary"`. La pubblicazione ufficiale del *modello di categorizzazione* ACN da parte del Tavolo NIS è prevista per maggio/giugno 2026. L'esportazione attuale è una mappatura strutturale best-effort basata sulla Determina 127437/2026 e verrà ri-convalidata una volta rilasciato il template ufficiale.

La checklist di governance include anche 3 elementi per la policy supply chain Art. 21(d).

## Business Impact Analysis (BIA)

### Stato: Implementato

Il modulo BIA è attivo. L'integrazione con il template ufficiale ACN verrà aggiunta alla sua pubblicazione.

- Inventario processi aziendali con livelli di criticità (1-4)
- RTO/RPO/MTPD per processo
- Punteggio d'impatto su 5 dimensioni
- Mappatura dipendenze asset e fornitori
- Rilevamento gap BCP/DRP
- Classificazione servizi ACN (essenziale/importante)
- Esportazione JSON compatibile ACN: `GET /api/v1/acn-export/bia`

## Segnalazione incidenti -- Art. 23 CSIRT

La piattaforma supporta la raccolta strutturata di informazioni per le notifiche al CSIRT Italia:

| Fase notifica | Scadenza | Supporto piattaforma |
|-------------------|---------|-----------------|
| Early Warning | Entro 24 ore | Il "Red Button" genera payload da 3 campi + inventario asset |
| Notifica Incidente | Entro 72 ore | Report strutturato con tassonomia UE, IOC, timeline |
| Report Finale | Entro 1 mese | Dati aggregati, valutazione impatto, lesson learned |

La piattaforma genera report strutturati compatibili con i requisiti di notifica ACN, semplificando la raccolta delle prove entro le scadenze previste dalla legge.

> **Nota:** La piattaforma non si interfaccia direttamente con il portale ACN. Genera dati strutturati che l'incaricato alle notifiche può inserire manualmente o attraverso i canali ufficiali ACN.

## Separazione NIS2 e GDPR

La piattaforma distingue nettamente tra i controlli NIS2 e i controlli GDPR/ePrivacy:

| Ambito | Controlli | Normativa |
|-------|--------|-----------|
| **NIS2 / D.Lgs 138/2024** | Sicurezza TLS, DNS, esposizione porte, salute certificati, segnalazione incidenti, checklist di governance | Direttiva (UE) 2022/2555 |
| **Privacy UE / Postura GDPR** | P.IVA, privacy policy, cookie banner | GDPR, Direttiva ePrivacy |

I due ambiti sono separati nell'interfaccia e nei report per evitare confusione normativa.

## Informazioni sul modulo

Questo modulo è un **ponte open-source** per agevolare la conformità NIS2 degli enti italiani. Non sostituisce i portali e i template ufficiali ACN, ma semplifica la raccolta, la verifica e l'esportazione dei dati richiesti per la conformità normativa.

Per supporto nell'implementazione o licenze commerciali: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)
