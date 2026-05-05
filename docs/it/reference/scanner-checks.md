# Controlli dello Scanner

Lo scanner esegue controlli automatizzati verso ogni target. I controlli sono raggruppati per categoria e mappati sugli articoli dell'Art. 21 della direttiva NIS2.

## Scansione delle Porte (Port Scanning)

Scansiona la presenza di porte aperte sui seguenti servizi:

| Porta | Servizio |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8080 | HTTP Alternate |
| 8443 | HTTPS Alternate |
| 27017 | MongoDB |

Ogni porta viene sondata con una connessione TCP asincrona (timeout di 2 secondi). Vengono generati finding per l'esposizione di porte di gestione (SSH, RDP, Telnet, SMB), protocolli in chiaro (FTP, HTTP, Telnet) e porte relative ai database (MySQL, PostgreSQL, Redis, MongoDB).

## TLS/SSL

- **Rilevamento versione protocollo**: si connette alla porta 443/8443 e legge la versione TLS negoziata.
- **Sondaggio versioni deboli**: tenta connessioni forzando singolarmente TLS 1.0 e TLS 1.1. Segnala il server se accetta queste versioni deprecate.
- **Rilevamento cipher**: riporta la suite di cifratura negoziata nella connessione principale.
- **Validazione certificato**: usa il modulo `ssl` di Python per recuperare il certificato del server. Verifica l'affidabilità della catena e la corrispondenza dell'hostname.

## Header di Sicurezza HTTP

Verifica la presenza dei seguenti header nelle risposte HTTP/HTTPS:

| Header | Scopo |
|---|---|
| `Strict-Transport-Security` | Imposizione dell'HTTPS (HSTS) |
| `Content-Security-Policy` | Mitigazione di XSS e injection |
| `X-Frame-Options` | Protezione dal Clickjacking |

Lo scanner registra tutti gli header di risposta. Vengono catturati anche gli header che espongono informazioni (information leakage): `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.

## Sicurezza DNS

I controlli DNS utilizzano `dnspython` e sono eseguiti in un thread executor per evitare di bloccare il loop asincrono.

- **DNSSEC**: interroga i record `DNSKEY` sul dominio. Se presenti, DNSSEC viene segnalato come abilitato.
- **Trasferimento di zona (AXFR)**: risolve i record NS del dominio, quindi tenta un trasferimento AXFR verso ciascun nameserver. Segnala il dominio se uno qualsiasi dei nameserver lo consente.
- **SPF**: interroga i record TXT del dominio e cerca un record che inizi con `v=spf1`.
- **DMARC**: interroga i record TXT su `_dmarc.<dominio>` e cerca un record che inizi con `v=DMARC1`.

I controlli DNS vengono eseguiti solo quando il target è un dominio (non un indirizzo IP o un range CIDR).

## Conformità Legale

I controlli legali utilizzano `playwright` (browser headless) per renderizzare la pagina e analizzare il DOM. Vengono eseguiti solo sui domini principali e sui sottodomini `www.`, non sugli indirizzi IP o sui sottodomini dei servizi.

- **P.IVA (Partita IVA)**: cerca un pattern di Partita IVA italiana (11 cifre) nel contenuto della pagina. Requisito obbligatorio per i siti commerciali in Italia.
- **Privacy policy**: cerca parole chiave come "privacy policy", "informativa privacy" all'interno della pagina renderizzata.
- **Cookie banner**: cerca parole chiave relative al consenso dei cookie ("cookie", "accetta", "accept cookies", "gestisci cookie", ecc.) nella pagina renderizzata.

## Rilevamento Segreti

Scansiona il corpo HTML delle risposte HTTP alla ricerca di segreti esposti. Lo scanner verifica l'eventuale presenza dei seguenti pattern (definiti in `secrets.py`):

| Pattern | Descrizione |
|---|---|
| `AKIA[0-9A-Z]{16}` | Chiavi di accesso AWS |
| `aws_secret_access_key = ...` | Chiavi segrete AWS |
| `-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----` | Chiavi private (RSA, EC, DSA) |
| `ghp_[a-zA-Z0-9]{36}` | Personal access token di GitHub |
| `api[_-]?key[:=] ...` | Assegnazioni generiche di chiavi API (valori di oltre 20 caratteri) |
| `eyJ...` (tre segmenti Base64 separati da punti) | Token JWT nel codice sorgente della pagina |

## WHOIS

- **Scadenza del dominio**: utilizza `python-whois` per recuperare la data di scadenza del dominio. Segnala i domini in scadenza entro 30 giorni.

I controlli WHOIS vengono eseguiti solo quando il target è un dominio.

## Rilevamento WAF/CDN

Rileva la presenza di Web Application Firewall e provider CDN abbinando gli header di risposta e i valori dei cookie a indicatori noti:

- Cloudflare (header cf-ray, cookie __cfduid)
- Akamai (header x-akamai)
- AWS CloudFront (header x-amz-cf-id)
- Fastly (header x-fastly)
- Incapsula/Imperva (cookie incap_ses, visid_incap)
- Sucuri (header x-sucuri-id)

## File Sensibili

Effettua un sondaggio per file che non dovrebbero essere accessibili pubblicamente:

| Percorso | Logica di Rilevamento |
|---|---|
| `/.git/HEAD` | Restituisce 200 e il body contiene `ref: refs/` |
| `/.env` | Restituisce 200 e il body contiene `=` |

Le risposte vengono convalidate per evitare falsi positivi derivanti da pagine 404 personalizzate che restituiscono HTTP 200.

## security.txt

Verifica la presenza di `/.well-known/security.txt` secondo la RFC 9116. In caso il percorso well-known non restituisca un codice 200, ricade su `/security.txt`.

## Subresource Integrity (SRI)

Analizza il body HTML in cerca di tag `<script>` esterni (quelli con l'attributo `src` che puntano a un host differente). Segnala gli script che non includono un attributo `integrity` (SRI).

## Sicurezza dei Cookie

Analizza gli header `Set-Cookie` presenti nella risposta HTTP:

- Flag **Secure**: il cookie dovrebbe essere inviato solo tramite HTTPS.
- Flag **HttpOnly**: il cookie non dovrebbe essere accessibile tramite JavaScript.
- Attributo **SameSite**: protezione dalle vulnerabilità CSRF.
