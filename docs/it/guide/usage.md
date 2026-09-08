# Utilizzo

## Asset

Gli asset sono i domini, gli indirizzi IP e gli intervalli CIDR che la piattaforma scansiona e monitora.

### Aggiungere un asset

1. Vai ad **Asset** nella barra laterale.
2. Clicca su **Aggiungi Asset**.
3. Compila:
   - **Nome**: etichetta leggibile (es. `Sito web aziendale`, `Rete interna`)
   - **Tipo di target**: `domain`, `ip`, o `cidr`
   - **Valore del target**: il valore effettivo (es. `esempio.it`, `10.0.0.1`, `192.168.0.0/24`)
   - **Tag** (opzionale): etichette libere per raggruppamento e filtraggio
4. Salva l'asset. Viene creato come `unverified` e **non è ancora
   scansionabile**: vedi sotto.

### Dimostrare l'autorità su un target

`POST /scans` rifiuta un target non verificato con un 403. Senza quel blocco
qualunque account potrebbe puntare lo scanner — scansione delle porte, tentativi
di zone transfer, richieste a `/.env` — verso infrastrutture con cui non ha
alcun rapporto, e a risponderne sarebbe chi gestisce l'istanza.

Apri l'asset e usa **Verifica proprietà**:

- **Dominio** — la piattaforma emette una sfida DNS TXT. Pubblica il record
  indicato sotto `_nis2-challenge.<dominio>` e premi verifica: l'asset diventa
  `verified`. È una prova, lo stesso meccanismo del DNS-01 di Let's Encrypt.
- **Indirizzo IP o intervallo CIDR** — qui il DNS non può provare nulla, quindi
  un amministratore registra al suo posto una dichiarazione di autorità
  nominativa e datata, conservata nell'audit log e attribuita a chi l'ha fatta.
  I domini non possono usare questa strada: hanno prove disponibili, e
  l'attestazione non deve diventare la scorciatoia per aggirarle.

Gli asset creati prima dell'introduzione della verifica hanno stato `legacy` e
continuano a funzionare; ovunque altro sono mostrati come non verificati.

### Importazione massiva

Clicca su **Importa** nella pagina Asset. Carica un file CSV con le colonne:

```
name,target_type,target_value,tags
Sito web aziendale,domain,esempio.it,web;esterno
Rete uffici,cidr,10.0.0.0/8,interno
```

`tags` è opzionale e separato da punto e virgola. Le righe con tipo o valore di target non validi vengono rifiutate e riportate nel riepilogo dell'importazione.

---

## Scansioni

### Scansione manuale

1. Vai a **Scansioni** e clicca su **Nuova Scansione**.
2. Seleziona uno o più asset.
3. Opzionalmente configura:
   - **Tipo di scansione**: `full` (tutti i controlli), `quick` (solo TLS e header), o `custom`
   - **Controlli**: abilita o disabilita port scanning, controlli web, controlli DNS, WHOIS
   - **Concorrenza**: task paralleli (predefinito: 20)
   - **Timeout**: secondi per controllo (predefinito: 10)
4. Clicca su **Avvia Scansione**. La scansione viene messa in coda immediatamente.

Valori di stato della scansione:

| Stato | Significato |
|---|---|
| `pending` | In coda, in attesa di un Celery worker |
| `running` | Esecuzione in corso |
| `completed` | Tutti i controlli completati, finding disponibili |
| `cancelled` | Interrotta da un utente prima del completamento |
| `failed` | Errore non recuperabile durante l'esecuzione |

### Annullare una scansione

Una scansione in stato `pending` o `running` può essere annullata dall'elenco Scansioni tramite l'azione **Annulla**. Il task Celery viene revocato e lo stato impostato a `cancelled`.

---

## Finding

La pagina **Finding** elenca tutti i problemi rilevati in tutte le scansioni dell'organizzazione.

### Filtri

| Filtro | Opzioni |
|---|---|
| Gravità | `critical`, `high`, `medium`, `low`, `info` |
| Stato | `open`, `acknowledged`, `in_progress`, `resolved`, `accepted_risk` |
| Categoria | TLS, DNS, Header, Porte, Segreti, Legale, WHOIS |

### Dettaglio finding

Ogni finding include:
- **Nome del controllo** e categoria
- **Gravità** con motivazione CVSS
- **Articolo NIS2** di riferimento (es. Art. 21(h) per i problemi TLS)
- **Descrizione** di quanto rilevato
- **Passi di remediation** — indicazioni specifiche e operative

### Aggiornare lo stato di un finding

Aggiorna lo stato di un singolo finding dalla sua pagina di dettaglio. Usa **Aggiornamento Massivo** nell'elenco Finding per aggiornare più finding contemporaneamente — utile quando si acquisisce consapevolezza di un gruppo di finding dopo un ciclo di revisione.

---

## Matrice di Conformità

La **Matrice di Conformità** mappa i finding della scansione ai sotto-paragrafi dell'Art. 21 NIS2 (da a a j).

- La matrice legge il campo `compliance_matrix` dell'ultima scansione completata.
- Ogni riga rappresenta un articolo NIS2; ogni colonna mostra se l'articolo ha finding aperti e quanti.
- Usala per avere una visione rapida degli articoli coperti e di quelli con problemi aperti.

---

## Report

I report esportano i dati della scansione in formato adatto a presentazioni al CDA, consegne all'auditor o notifiche al CSIRT.

### Generare un report

1. Vai a **Report** e clicca su **Genera Report**.
2. Seleziona una scansione completata.
3. Scegli un formato:
   - **PDF**: il dossier NIS2 completo, non solo la matrice di scansione. Dalla v2.6.0 include le sezioni governance (Art. 21), incidenti (Art. 23), filiera (Art. 18) e BIA, un donut del punteggio, una heatmap di copertura Art. 21 a-j e la distribuzione per severità. Prodotto in PDF/A-2b, taggato e accessibile, con font incorporato e localizzato in tutte le lingue supportate
   - **JSON**: leggibile da macchina, include dettaglio completo dei finding
   - **CSV**: esportazione tabellare dei finding per analisi su foglio di calcolo
   - **HTML**: pagina autonoma per archiviazione
   - **JUnit XML**: per integrazione con pipeline CI/CD
4. La generazione del report avviene in modo asincrono come task Celery.
5. Monitora lo stato nella pagina Report; scarica quando il report è pronto.

I report vengono conservati per `REPORT_TTL_DAYS` giorni (predefinito: 30) e poi rimossi automaticamente.

---

## Scansioni Schedulate

Automatizza scansioni ricorrenti con schedule basate su cron.

### Creare uno schedule

1. Vai a **Schedule** e clicca su **Nuovo Schedule**.
2. Seleziona gli asset target.
3. Imposta un'espressione cron:
   - `0 2 * * 1` — ogni lunedì alle 02:00
   - `0 3 * * *` — ogni giorno alle 03:00
   - `0 0 1 * *` — il primo giorno di ogni mese
4. Configura i parametri di scansione (stesse opzioni della scansione manuale).
5. Salva. Celery Beat lo raccoglie e avvia le scansioni alla cadenza specificata.

### Eseguire uno schedule immediatamente

Usa l'azione **Esegui Ora** su qualsiasi schedule per avviarlo fuori dalla cadenza ordinaria. Questo crea una normale esecuzione di scansione e non influenza la prossima esecuzione pianificata.

---

## Confronto Scansioni

Confronta due scansioni completate per tracciare i progressi della remediation.

1. Dalla pagina **Scansioni**, seleziona due scansioni completate dell'organizzazione.
2. La vista di confronto mostra:
   - **Finding nuovi**: presenti nella scansione che hai aperto e assenti in
     quella con cui la confronti — quindi, confrontando una scansione recente
     con una più vecchia, ciò che è comparso da allora.
   - **Finding risolti**: presenti nella scansione di confronto e assenti in
     quella che hai aperto: il controllo ora passa.
   - **Finding persistenti**: presenti in entrambe le scansioni (non risolti).
   - **Delta punteggio**: differenza numerica nel punteggio di conformità totale.

La direzione conta: l'endpoint è `GET /api/v1/scans/{scan_id}/compare/{other_id}`
e "nuovo" significa *presente in `scan_id`, assente in `other_id`*. Apri la
scansione più recente e confrontala con quella più vecchia, altrimenti le due
colonne si leggono al contrario.

---

## Governance

La sezione **Governance** copre i requisiti organizzativi e non tecnici di NIS2 che lo scanner non può valutare.

### Checklist

La checklist a 30 voci incrocia i sotto-paragrafi dell'Art. 21 NIS2. Ogni voce ha:
- Uno stato (`pending`, `in_progress`, `compliant`, `not_applicable`)
- Un responsabile (testo libero — es. `IT Manager`, `Legale`, `CISO`)
- Un campo evidenza (riferimento documentale o URL)

Consulta [Checklist-Governance](../governance/checklist.md) per l'elenco completo delle voci e le istruzioni d'uso.

### Registro Rischi

Il registro rischi si integra con i finding dello scanner. Chiamando `POST /api/v1/governance/sync-risk` si escalano automaticamente le voci della checklist quando sono presenti finding aperti di gravità `high` o `critical` per l'articolo corrispondente. `GET /api/v1/governance/risk-summary` restituisce una vista strutturata dei rischi aperti per articolo NIS2.

---

## Gestione Incidenti (Art. 23)

Traccia gli incidenti dal rilevamento attraverso il ciclo di vita della notifica CSIRT.

### Ciclo di vita dell'incidente

| Fase | Scadenza legale | Supporto piattaforma |
|---|---|---|
| Early Warning | 24 ore dal rilevamento | Genera un JSON Early Warning pronto per il CSIRT; Celery Beat invia alert alla scadenza e 2 ore prima |
| Notifica Incidente | 72 ore dal rilevamento | Modulo strutturato con tassonomia UE, IOC e timeline; stessa logica di alert |
| Rapporto Finale | 1 mese dal rilevamento | Valutazione dell'impatto aggregato e lessons learned; stessa logica di alert |

Gli alert vengono inviati tramite canali di notifica configurati (email, webhook firmato HMAC-SHA256, Slack). La deduplicazione è gestita su Redis — lo stesso alert non viene inviato due volte per lo stesso incidente e la stessa scadenza.

**La trasmissione a CSIRT Italia** (`csirt.gov.it`) è un passaggio manuale. La piattaforma produce gli elaborati e traccia le scadenze; non invia direttamente al portale CSIRT.

---

## Vendor Risk Management (Art. 18)

Monitora i fornitori terzi e valuta la loro postura di sicurezza.

### Aggiungere un fornitore

Vai a **Fornitori** e clicca su **Aggiungi Fornitore**. Campi obbligatori:
- **Nome** e **criticità** (1 = bassa, 4 = critica)
- **Livello di accesso ai dati**: nessuno / pseudonimizzati / personali / sensibili
- **Localizzazione geografica** del trattamento dati

I campi opzionali influenzano il punteggio:
- Certificazioni ISO 27001, SOC 2, CSA STAR
- Recenza dell'audit
- Clausole di sicurezza e SLA nel contratto
- Flag di rilevanza Art. 18 ACN (Italia)

### Punteggio fornitore

Ogni fornitore riceve un punteggio di sicurezza da 0 a 100 calcolato con una formula documentata. La formula e i pesi sono accessibili pubblicamente all'endpoint `GET /api/v1/vendors/score-formula` — gli auditor possono verificare il calcolo in modo indipendente.

---

## Pagine della dashboard

Dalla v2.6.0 le funzioni che erano solo API hanno un'interfaccia completa. Nella barra laterale:

| Pagina | Route | Cosa mostra |
|---|---|---|
| Incidenti | `/dashboard/incidents` | Il monitor delle scadenze Art. 23, con conto alla rovescia per gli obblighi a 24 ore, 72 ore e 1 mese |
| Governance | `/dashboard/governance` | La checklist Art. 21 da 30 voci, il punteggio pesato e un pulsante che esegue il ponte scanner-conformità in tempo reale |
| Fornitori | `/dashboard/vendors` | Rischio di filiera Art. 18: criticità, accesso ai dati, punteggio di sicurezza |
| Impatto sul business | `/dashboard/bia` | La tabella di continuità: RTO, RPO, MTPD, BCP e DRP per processo |

Tutte le pagine sono localizzate in tutte e cinque le lingue supportate.

---

## Business Impact Analysis

La pagina BIA registra, per ogni processo di business, gli obiettivi di ripristino che NIS2 si aspetta siano stati definiti: **RTO** (per quanto puoi restare fermo), **RPO** (quanti dati puoi permetterti di perdere) e **MTPD** (il punto oltre il quale il danno non è più recuperabile), insieme all'esistenza di un piano di continuità operativa e di un piano di disaster recovery.

Il valore non è la tabella in sé, sono i vuoti che rende visibili: un processo con RTO di due ore e nessun DRP è una contraddizione documentata, ed è esattamente ciò che un auditor chiede.

---

## Gestione Team

Gestisci i membri dell'organizzazione in **Impostazioni > Team**.

### Ruoli

| Ruolo | Permessi |
|---|---|
| `admin` | Accesso completo, gestione membri e impostazioni, generazione chiavi API |
| `auditor` | Eseguire scansioni, visualizzare tutti i dati, generare report, gestire schedule |
| `viewer` | Accesso in sola lettura a scansioni, finding e report |

### Invitare membri

Clicca su **Invita Membro**, inserisci l'indirizzo email e seleziona un ruolo. L'invito viene inviato per email. L'invitato si registra o accede e viene aggiunto all'organizzazione.

### Organizzazioni multiple

Un utente può appartenere a più organizzazioni con ruoli diversi in ciascuna. Usa il selettore di organizzazione nella barra di navigazione superiore per cambiare l'organizzazione attiva.

---

## Chiavi API

Le chiavi API forniscono accesso programmatico all'API REST senza richiedere l'autenticazione basata su cookie.

### Creare una chiave API

1. Vai a **Impostazioni > Chiavi API**.
2. Clicca su **Crea Chiave API**, assegna un nome e seleziona gli scope:
   - `scan:read`, `scan:write`
   - `finding:read`
   - `asset:read`
   - `report:read`
3. Il valore grezzo della chiave viene mostrato una sola volta alla creazione. Copialo subito.

Le chiavi API sono conservate come hash bcrypt. Il valore grezzo non può essere recuperato dopo la creazione.

### Revocare una chiave API

Elimina la chiave da **Impostazioni > Chiavi API**. La revoca è immediata.

---

## Autenticazione a Due Fattori (TOTP)

La piattaforma supporta MFA basata su TOTP (RFC 6238) per gli account utente. L'MFA è facoltativa per utente e soddisfa i requisiti NIS2 Art. 21(j) sui controlli di autenticazione.

### Abilitare il TOTP

1. Vai a **Impostazioni > Sicurezza**.
2. Clicca su **Abilita Autenticazione a Due Fattori**.
3. Scansiona il codice QR con un'app di autenticazione (Google Authenticator, Authy, ecc.).
4. Inserisci un codice dall'app per confermare la configurazione.

Una volta abilitato, l'accesso richiede sia la password sia un codice TOTP valido.

### Disabilitare il TOTP

Da **Impostazioni > Sicurezza**, clicca su **Disabilita Autenticazione a Due Fattori** e inserisci un codice TOTP corrente per confermare.
