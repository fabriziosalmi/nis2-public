# Riferimento API

La Piattaforma NIS2 espone un'API REST all'indirizzo `http://localhost:8000`. Tutte le rotte sono precedute dal prefisso `/api/v1/`. La documentazione interattiva OpenAPI è disponibile in `/docs` (Swagger UI) e `/redoc` (ReDoc).

Tutti gli endpoint restituiscono JSON. Due modalità di autenticazione sono accettate su ogni rotta protetta:

- **Sessione con Cookie (web)** — Cookie `access_token` httpOnly impostato da `/auth/login` o `/auth/register`. Le richieste che modificano lo stato devono inviare nuovamente il cookie `csrf_token` tramite l'header `X-CSRF-Token` (pattern double-submit).
- **Token Bearer (SDK / CLI)** — Header `Authorization: Bearer <jwt>`. I token emessi da `/auth/login` sono validi; in questa modalità può essere utilizzato lo stesso access token del cookie.

Gli endpoint di sola lettura sotto **scansioni / findings / asset** accettano inoltre una **Chiave API** a lunga scadenza nel formato `Authorization: Bearer nis2_…` (nessun cookie richiesto). Le chiavi vengono emesse tramite `POST /api/v1/api-keys` (solo admin) e il valore grezzo viene mostrato una sola volta. Gli endpoint di mutazione (POST / PATCH / DELETE) su tali risorse richiedono comunque una sessione: le colonne di audit log e `created_by` necessitano infatti di un'identità utente a cui attribuire la modifica.

## Autenticazione

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Registra un nuovo utente e crea un'organizzazione. Restituisce token di accesso e di aggiornamento (impostati anche come cookie httpOnly per il client web) | No |
| POST | `/api/v1/auth/login` | Ottiene i token di accesso e di aggiornamento | No |
| POST | `/api/v1/auth/refresh` | Ruota il token di accesso utilizzando il cookie del token di aggiornamento. I refresh token sono monouso (jti tracciato in `revoked_tokens`); il riutilizzo di uno di essi revoca l'intera famiglia | No |
| POST | `/api/v1/auth/logout` | Pulisce i cookie e revoca il token di aggiornamento | Sì |
| GET | `/api/v1/auth/me` | Ottiene il profilo dell'utente corrente | Sì |
| PATCH | `/api/v1/auth/me` | Aggiorna il profilo dell'utente corrente (nome / locale / avatar). **Non** accetta `current_password` / `new_password` — vedi `/auth/change-password` | Sì |
| POST | `/api/v1/auth/change-password` | Cambia la password dell'utente. Verifica `current_password`, esegue l'hash di `new_password`, marca la data in `password_changed_at` (invalidando alla prima richiesta tutte le altre sessioni attive) e riemette i cookie per questa sessione. Rate limit: `5/min/IP` | Sì |
| POST | `/api/v1/auth/forgot-password` | Avvia il flusso di ripristino via email. Restituisce sempre 204 a prescindere dall'esistenza dell'email, in modo da non permettere l'enumerazione degli utenti. Rate limit: `5/min/IP` | No |
| POST | `/api/v1/auth/reset-password` | Completa il flusso di ripristino con un token monouso (inviato out-of-band via email) e una nuova password. I token sono sottoposti ad hash sha256 a riposo, scadono dopo `RESET_TOKEN_TTL_MINUTES` (default 30) e un singolo 400 copre gli stati {sconosciuto, scaduto, usato} — impedendo attacchi oracolo. Rate limit: `10/min/IP` | No |
| POST | `/api/v1/auth/switch-org` | Cambia l'organizzazione attiva per la sessione corrente. Body: `{"organization_id": "<uuid>"}`. Valida che il chiamante sia membro dell'organizzazione target (altrimenti 403), dopodiché emette nuovi token access / refresh / csrf con il claim `org_id` aggiornato e ruota i cookie. Restituisce `TokenResponse` (stessa struttura di `/login`). Rate limit: `10/min/IP` | Sì |

## Scansioni

Legenda colonna `Auth`: **Sessione** = cookie o `Bearer <jwt>`. **Chiave API** = ammesso anche `Bearer nis2_…` (cookie non richiesto).

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/scans` | Elenca le scansioni per l'organizzazione corrente. Filtrabile tramite `status`. Impaginato | Sessione o Chiave API |
| POST | `/api/v1/scans` | Crea e accoda una nuova scansione | Sessione |
| GET | `/api/v1/scans/{scan_id}` | Ottiene i dettagli e lo stato della scansione | Sessione o Chiave API |
| DELETE | `/api/v1/scans/{scan_id}` | Elimina una scansione e i relativi finding (solo admin) | Sessione |
| GET | `/api/v1/scans/{scan_id}/results` | Elenca i risultati grezzi di una scansione. Impaginato | Sessione o Chiave API |
| GET | `/api/v1/scans/{scan_id}/findings` | Elenca i finding di una scansione. Impaginato | Sessione o Chiave API |
| POST | `/api/v1/scans/{scan_id}/cancel` | Annulla una scansione in coda o in esecuzione | Sessione |
| GET | `/api/v1/scans/{scan_id}/compare/{other_id}` | Confronta due scansioni: scarto del punteggio, finding nuovi/risolti/persistenti | Sessione o Chiave API |

## Risultati (Findings)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/findings` | Elenca tutti i finding. Filtrabile per `severity`, `status`, `category`. Impaginato | Sessione o Chiave API |
| GET | `/api/v1/findings/stats` | Ottiene il conteggio dei finding raggruppati per gravità e stato | Sessione o Chiave API |
| GET | `/api/v1/findings/{finding_id}` | Ottiene i dettagli del finding | Sessione o Chiave API |
| PATCH | `/api/v1/findings/{finding_id}` | Aggiorna lo stato del finding o la nota di risoluzione | Sessione |
| POST | `/api/v1/findings/bulk-update` | Aggiornamento in massa (bulk) dello stato per più finding | Sessione |

## Asset

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/assets` | Elenca gli asset dell'organizzazione corrente. Impaginato | Sessione o Chiave API |
| POST | `/api/v1/assets` | Crea un nuovo asset | Sessione |
| GET | `/api/v1/assets/{asset_id}` | Ottiene i dettagli dell'asset | Sessione o Chiave API |
| PATCH | `/api/v1/assets/{asset_id}` | Aggiorna un asset | Sessione |
| DELETE | `/api/v1/assets/{asset_id}` | Elimina un asset | Sessione |
| POST | `/api/v1/assets/import` | Importa asset da un file CSV | Sessione |

## Pianificazioni (Schedules)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/schedules` | Elenca le pianificazioni di scansione | Sì |
| POST | `/api/v1/schedules` | Crea una pianificazione (espressione cron). Solo admin o auditor | Sì |
| PATCH | `/api/v1/schedules/{schedule_id}` | Aggiorna una pianificazione | Sì |
| DELETE | `/api/v1/schedules/{schedule_id}` | Elimina una pianificazione | Sì |
| POST | `/api/v1/schedules/{schedule_id}/run` | Attiva immediatamente un'esecuzione manuale della pianificazione | Sì |

## Report

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| POST | `/api/v1/reports/generate` | Accoda la generazione del report. Parametri: `scan_id`, `format` (pdf, html, markdown, json, csv, junit). Restituisce un `task_id`. **Deduplicazione**: richieste identiche entro 5 min restituiscono il `task_id` esistente con `deduplicated: true`. Rate limit `5/min/IP`. Il report è renderizzato nella lingua dell'utente | Sì |
| GET | `/api/v1/reports/status/{task_id}` | Controlla lo stato della generazione del report tramite ID del task Celery | Sì |
| GET | `/api/v1/reports/download/{task_id}` | Scarica un report generato | Sì |

## Organizzazioni

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/organizations` | Elenca le organizzazioni a cui appartiene l'utente corrente | Sì |
| POST | `/api/v1/organizations` | Crea una nuova organizzazione | Sì |
| GET | `/api/v1/organizations/{org_id}` | Ottiene i dettagli dell'organizzazione | Sì |
| PATCH | `/api/v1/organizations/{org_id}` | Aggiorna le impostazioni dell'organizzazione (solo admin) | Sì |
| GET | `/api/v1/organizations/{org_id}/members` | Elenca i membri dell'organizzazione | Sì |
| POST | `/api/v1/organizations/{org_id}/members` | Invita un membro tramite email (solo admin) | Sì |
| PATCH | `/api/v1/organizations/{org_id}/members/{member_id}` | Aggiorna il ruolo di un membro (solo admin) | Sì |
| DELETE | `/api/v1/organizations/{org_id}/members/{member_id}` | Rimuove un membro (solo admin). Non può rimuovere l'ultimo admin | Sì |

## Integrità (Health)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/health` | Controllo di liveness. Restituisce `{"status": "ok"}` | No |
| GET | `/api/v1/health/ready` | Controllo di readiness. Testa la connettività al database e Redis | No |

## Certificati

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| POST | `/api/v1/certificates/check` | Analisi profonda dei certificati per un singolo dominio. Restituisce catena, OCSP, log CT, forza della chiave, punteggio da 0-100 | Sì |
| POST | `/api/v1/certificates/bulk-check` | Analizza fino a 50 domini in blocco con statistiche riepilogative | Sì |
| GET | `/api/v1/certificates/ct-logs/{domain}` | Interroga i registri di Certificate Transparency via crt.sh | Sì |

## Remediation

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/remediation/playbooks` | Elenca tutti i playbook di remediation disponibili | No |
| GET | `/api/v1/remediation/playbooks/{id}` | Ottiene l'intero playbook con step, config e stime dell'effort | No |
| GET | `/api/v1/remediation/for-finding/{finding_id}` | Assegna automaticamente il playbook migliore per uno specifico finding | Sì |
| GET | `/api/v1/remediation/estimate/{scan_id}` | Calcola l'effort e il costo totale della remediation per l'intera scansione | Sì |
| POST | `/api/v1/remediation/explain/{finding_id}` | Spiegazione potenziata dall'AI del finding. Prova prima il LLM locale, poi OpenAI, infine ricade sui playbook | Sì |

## Incidenti

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| POST | `/api/v1/incidents` | Segnala un incidente (Tassonomia Art. 23 CSIRT) | Sì |
| GET | `/api/v1/incidents` | Elenca gli incidenti dell'organizzazione | Sì |
| GET | `/api/v1/incidents/{id}` | Dettagli di un incidente | Sì |
| PATCH | `/api/v1/incidents/{id}` | Aggiorna i dettagli o lo stato dell'incidente | Sì |

## Governance

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/governance/checklist` | Ottiene i 30 elementi della checklist di governance NIS2 coi relativi stati | Sì |
| PATCH | `/api/v1/governance/checklist/{item_id}` | Aggiorna lo stato di una voce della checklist | Sì |
| POST | `/api/v1/governance/seed` | Popola la checklist dal template di governance | Sì |
| GET | `/api/v1/governance/score` | Ottiene il punteggio di conformità pesato | Sì |

## Chiavi API

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/api-keys` | Elenca le chiavi API dell'organizzazione (admin o auditor) | Sì |
| POST | `/api/v1/api-keys` | Crea una nuova chiave API (solo admin). Il token grezzo è mostrato solo una volta | Sì |
| DELETE | `/api/v1/api-keys/{key_id}` | Revoca una chiave API (solo admin) | Sì |

## Audit Log

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/audit-logs` | Elenca le voci di audit per l'organizzazione. Filtrabile. Impaginato | Sì |

## Fornitori (Art. 18 Supply Chain)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/vendors` | Elenca i fornitori dell'organizzazione, ordinati per criticità | Sì |
| POST | `/api/v1/vendors` | Registra un nuovo fornitore/supplier | Sì |
| GET | `/api/v1/vendors/stats` | Panoramica del rischio della supply chain | Sì |
| GET | `/api/v1/vendors/{vendor_id}` | Dettagli del fornitore | Sì |
| PATCH | `/api/v1/vendors/{vendor_id}` | Aggiorna dettagli, stato o assessment di sicurezza | Sì |
| DELETE | `/api/v1/vendors/{vendor_id}` | Rimuove un fornitore | Sì |

## Analisi di Impatto Aziendale (BIA)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/bia` | Elenca i processi aziendali dell'organizzazione | Sì |
| POST | `/api/v1/bia` | Registra un processo aziendale per la BIA | Sì |
| GET | `/api/v1/bia/matrix` | Matrice d'impatto BIA | Sì |
| GET | `/api/v1/bia/{process_id}` | Dettagli del processo aziendale | Sì |
| DELETE | `/api/v1/bia/{process_id}` | Rimuove un processo aziendale | Sì |

## Esportazione ACN (Italia)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/acn-export/art18` | Esporta l'inventario dei fornitori (Art. 18) in JSON compatibile ACN | Sì |
| GET | `/api/v1/acn-export/bia` | Esporta i dati BIA in JSON compatibile ACN | Sì |

## Scadenze di Conformità

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| GET | `/api/v1/deadlines` | Timeline delle scadenze di conformità NIS2 | No |

## Emergenza CSIRT (Art. 23)

| Metodo | Percorso | Descrizione | Auth |
|---|---|---|---|
| POST | `/api/v1/csirt/emergency` | Genera il payload di Early Warning per l'Art. 23 a partire da dati minimi | Sì |

## Errori (Risposte)

Tutti gli errori seguono un formato coerente:

```json
{
  "detail": "Descrizione dell'errore"
}
```

| Codice | Significato |
|---|---|
| 400 | Bad request (errore di validazione) |
| 401 | Unauthorized (token mancante o non valido) |
| 403 | Forbidden (permessi insufficienti) |
| 404 | Risorsa non trovata |
| 409 | Conflitto (risorsa duplicata) |
| 422 | Entità non elaborabile (corpo della richiesta non valido) |
| 429 | Troppe richieste (rate limit raggiunto) |
| 500 | Errore interno del server |
