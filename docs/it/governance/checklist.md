# Checklist Governance NIS2: 30 Priorità

## Come utilizzare questo documento

Questa checklist copre i requisiti organizzativi e di governance che non possono essere verificati mediante scansioni automatiche. Lo scanner controlla le misure tecniche (TLS, header, DNS, porte). Questa checklist affronta tutto il resto: policy, processi, formazione e obblighi legali.

Utilizzala in abbinamento alla Matrice di Conformità (Compliance Matrix) della piattaforma:

1. **Assessment**: esamina ogni voce e contrassegna lo stato attuale.
2. **Assegnazione**: assegna un responsabile a ogni voce mancante (es. "Responsabile IT" per i Backup, "Legale" per i Contratti).
3. **Tracciamento**: rivedi questo documento mensilmente durante le riunioni direzionali o del CdA.
4. **Evidenze**: conserva le prove di conformità (PDF, screenshot, log) in un repository sicuro referenziato all'interno del documento.

Questa checklist è ordinata secondo una logica di "Sopravvivenza e Conformità Legale": in primis le misure che prevengono sanzioni immediate e blocchi operativi, in seguito la strutturazione, e infine l'ottimizzazione.

## Riferimenti Ufficiali

- **Direttiva NIS2 (UE 2022/2555)**: [Testo Ufficiale (EUR-Lex)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- **Portale ACN (Italia)**: [Login per Registrazione](https://portale.acn.gov.it/login)
- **Linee Guida ENISA**: [Guida Tecnica di Implementazione](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance)
- **Template Policy SANS**: [Template Policy di Sicurezza delle Informazioni](https://www.sans.org/information-security-policy/)
- **Risorse della Community**: [Repository Awesome NIS2 Directive](https://github.com/CyberAlbSecOP/Awesome_NIS2_Directive)

---

## PRIORITÀ CRITICA (Obbligatori per Scadenza)

Senza queste misure, l'azienda è esposta legalmente o risulta priva di difese tecniche.

- [ ] **Scoping Analysis**: conferma definitiva se l'azienda è un soggetto "Essenziale" o "Importante" ai sensi del D.Lgs 138/2024 (o del recepimento locale).
- [ ] **Registrazione Portale ACN**: l'azienda si è registrata sul portale dell'Agenzia per la Cybersicurezza Nazionale? (Obbligo formale primario).
- [ ] **Governance - Responsabilità del CdA**: il CdA/Direzione ha formalmente assunto la responsabilità in ambito di cybersicurezza (verbali di approvazione)?
- [ ] **Governance - Formazione del Management**: i vertici aziendali hanno seguito i corsi di formazione obbligatoria in materia di cybersicurezza?
- [ ] **MFA (Multi-Factor Authentication)**: è attiva su tutti gli accessi remoti (VPN, Cloud) e sugli account privilegiati (Admin)?
- [ ] **Backup Immutabili/Offline**: esiste una copia dei dati critici scollegata dalla rete o immutabile (protezione anti-ransomware)?
- [ ] **Procedura di Notifica Incidenti (24h/72h)**: c'è una procedura scritta che definisce chi contatta il CSIRT entro 24 ore in caso di un attacco grave?
- [ ] **Inventario Asset**: c'è una lista aggiornata dell'hardware, del software e dei dati? (Non si può proteggere ciò che non si conosce).
- [ ] **Vulnerability Management (Patching)**: le patch di sicurezza critiche vengono installate entro tempistiche predefinite (es. 48-72h dal rilascio)?
- [ ] **Budget per la Cybersicurezza**: è stato allocato un budget specifico e adeguato per la conformità alla NIS2?

## ALTA PRIORITÀ (Processi Fondamentali)

Queste misure definiscono la capacità dell'azienda di gestire i rischi.

- [ ] **Risk Assessment**: è stata condotta un'analisi formale dei rischi informatici per tutti gli asset critici?
- [ ] **Policy sulla Sicurezza delle Informazioni**: esiste un documento "master" approvato che stabilisce le regole di sicurezza aziendali?
- [ ] **Mappatura Fornitori (Supply Chain)**: c'è un elenco dei fornitori critici (MSP, Software, Cloud)?
- [ ] **Sicurezza della Supply Chain**: nei contratti coi fornitori sono inclusi i requisiti di sicurezza e le clausole per la notifica degli incidenti?
- [ ] **Incident Response Plan (IR Plan)**: oltre alla notifica, esiste un piano tecnico su come contenere e sradicare un attacco?
- [ ] **Business Continuity Plan (BCP)**: esistono procedure per continuare a lavorare (anche manualmente) in caso l'IT fosse fuori uso?
- [ ] **Disaster Recovery Plan (DR)**: è stato definito e testato il ripristino dei sistemi IT a seguito di un disastro?
- [ ] **Formazione Dipendenti (Awareness)**: è attivo un programma di formazione anti-phishing continuo rivolto a tutto il personale?
- [ ] **Test dei Backup**: viene eseguito un test di ripristino dei dati almeno una volta ogni 6 mesi?
- [ ] **Controllo Accessi (Least Privilege)**: i dipendenti dispongono unicamente dei permessi strettamente necessari allo svolgimento delle proprie mansioni (nessun Admin locale ovunque)?

## PRIORITÀ MEDIA (Ottimizzazione e Igiene Informatica)

Misure tecniche e organizzative necessarie al raggiungimento della piena conformità.

- [ ] **Segmentazione di Rete**: la rete di produzione (OT) o dei reparti critici è separata da quella degli uffici e dei visitatori (guest)?
- [ ] **Onboarding/Offboarding**: c'è una checklist automatica per disabilitare e revocare gli accessi quando un dipendente lascia l'azienda?
- [ ] **Crittografia**: i dati sensibili vengono cifrati quando archiviati (at rest) e durante il transito in rete (in transit)?
- [ ] **Gestione delle Chiavi Crittografiche**: le chiavi di crittografia vengono gestite in modo sicuro e tenute separate dai dati?
- [ ] **Logging e Monitoraggio**: i log di sistema vengono raccolti in un punto centralizzato e analizzati per rilevare eventuali anomalie?
- [ ] **Sicurezza in fase di Sviluppo/Acquisizione**: i requisiti di sicurezza vengono analizzati e valutati preventivamente, prima dell'acquisto o dello sviluppo di nuovo software?
- [ ] **Comunicazioni Sicure**: vengono utilizzati sistemi sicuri per le comunicazioni di emergenza (es. Signal/Teams protetti) se la posta aziendale non è raggiungibile?
- [ ] **Audit Interni**: vengono programmati ed eseguiti controlli periodici per verificare il rispetto di tutte le procedure di sicurezza?
- [ ] **Vulnerability Assessment/Pen Test**: viene effettuata almeno annualmente una scansione o una simulazione di attacco per l'individuazione di vulnerabilità tecniche?
- [ ] **Uso di Crittografia End-to-End**: (Dove applicabile) viene implementata per garantire la protezione di comunicazioni di natura confidenziale e/o riservata.
