# Servizi Professionali

Piattaforma sviluppata e mantenuta da **Fabrizio Salmi**, consulente indipendente specializzato in conformità alla Direttiva NIS2 e sicurezza della supply chain.

## Per CISO e compliance officer

### Assessment di Conformità NIS2

Analisi completa dei gap su tutti i 10 sotto-paragrafi (a)-(j) dell'Art. 21:
- Mappatura dei controlli esistenti sui requisiti normativi
- Risk assessment con punteggio di gravità basato su CVSS
- Roadmap di remediation priorizzata con stime di effort e costi
- Presentazione della postura di conformità pronta per il CdA
- Supporto per le misure di sicurezza di base (Determina ACN 127434)

### Scansione NIS2 Privata (white-label)

Scansione completa dell'infrastruttura con report direzionale:
- Valutazione completa dell'Art. 21
- Analisi della catena dei certificati con priorità di remediation
- Audit della sicurezza DNS (SPF, DMARC, DKIM, DNSSEC)
- Analisi dell'esposizione delle porte con classificazione del rischio
- Deliverable: report PDF direzionale + foglio di calcolo con i dettagli tecnici (findings)

### Gestione Incidenti (Art. 23 CSIRT)

Supporto per la notifica al CSIRT entro le scadenze previste:
- Classificazione dell'incidente con tassonomia UE
- Ricostruzione della timeline e conservazione delle prove
- Stesura delle notifiche (early warning 24h, notifica 72h, report finale)
- Revisione post-incidente e lesson learned

## Per consulenti NIS2 e DPO

### Multi-tenant per consulenti

Architettura multi-organizzazione per gestire più clienti:
- Isolamento completo dei dati per ogni organizzazione
- Accesso basato su ruoli: admin, auditor, viewer
- Dashboard aggregata per monitorare tutti i clienti
- Report direzionali a supporto della fatturazione cliente
- Esportazione CSV/PDF per le presentazioni al CdA

## Servizi Tecnici

### Gestione del ciclo di vita dei certificati

Remediation TLS/SSL con [CertMate](https://github.com/fabriziosalmi/certmate) e CertMate-NG (privato -- [richiedi accesso](mailto:fabrizio.salmi@gmail.com)):
- Inventario certificati e tracciamento scadenze
- Validazione della catena e problemi legati ai certificati intermedi
- Configurazione di pipeline di rinnovo automatizzato (certbot, acme.sh)
- Monitoraggio OCSP e CT log
- Migrazione della forza della chiave (da RSA a ECDSA)

### Monitoraggio Continuo

Garanzia di conformità nel tempo:
- Scansioni pianificate (settimanali/mensili) con analisi dei trend
- Report trimestrali con progressione del punteggio
- Alert sulle scadenze dei certificati (avvisi a 30/15/7 giorni)
- Rilevamento e prioritizzazione di nuove vulnerabilità

### Personalizzazione Piattaforma

Deployment dedicati per esigenze specifiche:
- Deployment on-premise privato o in cloud
- Moduli scanner settoriali (sanità, finanza, energia)
- Template di report personalizzati col branding aziendale
- Integrazione SIEM/SOAR/ticketing (Jira, ServiceNow)
- Configurazione server MCP per flussi di lavoro assistiti dall'IA

### Formazione

Formazione su NIS2 e sicurezza:
- Panoramica NIS2 per i CdA (obblighi, sanzioni, scadenze)
- Formazione sulla sicurezza tecnica per i team di sviluppo e operations
- Formazione sulla piattaforma per i compliance officer interni

## Licenza Commerciale

La piattaforma è rilasciata sotto licenza AGPL-3.0. Per le organizzazioni che richiedono una **licenza commerciale senza obblighi copyleft**, sono disponibili accordi di doppia licenza.

## Contatti

**Fabrizio Salmi**
Email: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)
GitHub: [github.com/fabriziosalmi](https://github.com/fabriziosalmi)

Strumenti correlati:
- [CertMate](https://github.com/fabriziosalmi/certmate) -- Monitoraggio e gestione dei certificati
- CertMate-NG (privato -- [richiedi accesso](mailto:fabrizio.salmi@gmail.com))
