# Utilizzo

## Asset

Gli asset rappresentano i domini, gli IP o i range CIDR che desideri scansionare.

1. Vai alla sezione **Asset** nella barra laterale.
2. Clicca su **Aggiungi Asset** e inserisci un dominio (es. `example.com`), un indirizzo IP o un range CIDR.
3. Ogni asset ha un nome, un tipo target (domain, ip, cidr), un valore target e dei tag opzionali.

Puoi anche importare in massa gli asset da un file CSV tramite il pulsante **Importa**. Le colonne previste sono: `name`, `target_type`, `target_value`, `tags` (opzionale, separati da punto e virgola).

Gli asset appartengono alla tua organizzazione e sono visibili a tutti i membri in base al loro ruolo.

## Avvio delle Scansioni

1. Vai alla sezione **Scansioni** e clicca su **Nuova Scansione**.
2. Seleziona uno o più asset da scansionare.
3. Facoltativamente, configura il tipo di scansione (full, quick, custom), i toggle delle funzionalità (port scan, controlli web, controlli DNS, controlli WHOIS), la concorrenza e il timeout.
4. Clicca su **Avvia Scansione**. La scansione viene accodata come task Celery ed eseguita in background in modo asincrono.
5. Lo stato della scansione si aggiorna con il polling del frontend: pending (in coda), running (in esecuzione), completed (completata), cancelled (annullata) o failed (fallita).

## Visualizzazione dei Risultati (Findings)

La pagina **Findings** elenca tutti i problemi rilevati durante le scansioni.

- Filtra per gravità (critica, alta, media, bassa, info), stato o categoria.
- Ogni risultato include: nome del controllo, gravità, mappatura sull'articolo NIS2, descrizione e istruzioni per la remediation.
- Stati dei risultati: **open** (aperto), **acknowledged** (preso in carico), **in_progress** (in corso), **resolved** (risolto), **accepted_risk** (rischio accettato).
- Aggiorna lo stato di un singolo risultato o utilizza l'aggiornamento in massa (bulk) per modificare più risultati contemporaneamente.

## Matrice di Conformità

La **Matrice di Conformità** mappa i risultati (findings) sui requisiti dell'Art. 21 NIS2.

- La matrice legge dal campo `compliance_matrix` della scansione completata più di recente.
- Le righe rappresentano gli articoli NIS2; le colonne mostrano lo stato di conformità.
- Utilizzala per capire quali articoli presentano problemi e quali risultano conformi.

## Report

Genera report esportabili a partire dai risultati delle scansioni.

1. Vai alla sezione **Report** e clicca su **Genera Report**.
2. Seleziona una scansione completata e un formato (PDF, JSON o CSV).
3. La generazione del report viene eseguita in modo asincrono tramite Celery. Controlla lo stato o attendi che appaia come pronto, quindi scaricalo.

## Scansioni Pianificate

Automatizza le scansioni ricorrenti tramite una pianificazione basata su cron.

1. Vai su **Pianificazioni** (Schedules) e clicca su **Nuova Pianificazione**.
2. Seleziona gli asset, imposta un'espressione cron (es. `0 2 * * 1` per ogni lunedì alle 2:00 di notte).
3. Celery Beat invierà le scansioni come pianificato.
4. Puoi anche attivare immediatamente una scansione pianificata tramite l'azione **Esegui Ora** (Run Now).

## Confronto tra Scansioni

Confronta due scansioni per tenere traccia dei progressi della remediation.

1. Dalla pagina **Scansioni**, seleziona due scansioni completate qualsiasi nell'organizzazione.
2. La vista di confronto mostra:
   - **Nuovi risultati**: problemi presenti nella prima scansione ma non nella seconda.
   - **Risultati risolti**: problemi presenti nella seconda scansione ma non nella prima.
   - **Risultati persistenti**: problemi presenti in entrambe le scansioni.
   - **Variazione del punteggio (delta)**: la differenza di punteggio totale tra le due scansioni.

## Gestione del Team

Gestisci i membri dell'organizzazione in **Impostazioni > Team**.

- **Invita membri** tramite email. Riceveranno un invito a unirsi alla tua organizzazione.
- **Assegna ruoli**:
  - **Admin**: accesso completo, gestisce membri e impostazioni.
  - **Auditor**: avvia scansioni, visualizza tutti i dati, genera report.
  - **Viewer**: accesso in sola lettura a scansioni, risultati e report.
- **Aggiorna ruoli** o **rimuovi membri** secondo necessità.

## Chiavi API

Genera le chiavi API sotto **Impostazioni > Chiavi API** per l'accesso programmatico all'API REST. Le chiavi ereditano i permessi dell'utente che le ha create. Consulta il [Riferimento API](../reference/api.md) per la documentazione degli endpoint.
