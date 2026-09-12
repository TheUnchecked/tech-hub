# Raccolta di evidenze per assessment di conformità ADCS

Programmi PowerShell (5.1 e 7.x, Windows Server 2016+) per la raccolta di
evidenze — **mai la valutazione di conformità** — su una CA Microsoft ADCS
interna on-premise, ai fini di un assessment.

**IMPATTO: NESSUNO — SOLA LETTURA.** Nessun programma di questa raccolta
scrive configurazioni, registro, certificati, modelli, servizi o file al di
fuori della cartella indicata con `-PercorsoUscita`.

## Regole di sola lettura applicate

- Nessun cmdlet con verbo `Set`, `New`, `Remove`, `Add`, `Start`, `Stop`,
  `Restart`, `Install`, `Uninstall`, `Enable`, `Disable`, `Clear`, `Reset`,
  `Import`, `Revoke`, `Publish`.
- `certutil.exe` solo in interrogazione (`-dump`, `-getreg`, `-view`,
  `-CAInfo`, `-template`, `-CATemplates`, `-verify`, `-key`, `-ca.cert`,
  `-ca.crl`). `Comune.ps1` blocca esplicitamente ogni switch di scrittura
  noto (`-setreg`, `-installcert`, `-revoke`, ecc.) prima di ogni chiamata.
- Nessun `Invoke-Expression` né altra esecuzione dinamica di testo.
- Nessuna scrittura su `HKLM`/`HKCU`; nessuna scrittura su disco fuori da
  `-PercorsoUscita`, che deve già esistere — nessun programma crea cartelle
  (richiederebbe un verbo `New`/`Set`).
- Nessuna credenziale richiesta o gestita.

## Ordine di esecuzione

Eseguire **prima** `00-VerificaStrategiaPaginazione.ps1`: sonda empiricamente,
su intervalli ridotti, se la paginazione per `RequestId` o per data funziona
su questa CA/versione di Windows Server, e scrive `StrategiaPaginazione.json`
in `-PercorsoUscita`. I programmi 05/06/08, che leggono volumi potenzialmente
grandi, leggono questo file all'avvio; se assente, avvisano ed eseguono un
ripiego empirico rapido invece di usare una strategia cablata.

Gli altri programmi (01-04, 07, 09, 10) sono indipendenti tra loro e possono
essere eseguiti in qualsiasi ordine dopo 00.

## Programmi

| # | Programma | Copre |
|---|---|---|
| 00 | VerificaStrategiaPaginazione | Prerequisito tecnico per 05/06/08 |
| 01 | InventarioCA | Identità, tipo, catena, algoritmo/lunghezza chiave, HSM |
| 02 | ParametriConfigurazioneCA | CRL/validity period, AuditFilter, EditFlags |
| 03 | ModelliCertificato | Elenco modelli, flag di iscrizione/chiave privata, firme RA |
| 04 | PermessiModelliECA | ACL modelli (Enroll/Autoenroll), descrittore di sicurezza CA |
| 05 | CertificatiEmessi | Profili emessi, algoritmi deboli, scaduti non revocati |
| 06 | Revoca | CDP/AIA, metadati CRL, validazione OCSP/catena |
| 07 | RuoliESeparazioneCompiti | Titolari ruoli CA, RoleSeparation, admin locali |
| 08 | RegistrazioneEventi | AuditFilter, dimensione log, campione eventi audit |
| 09 | IndurimentoSistema | Servizi, porte, aggiornamenti, SCHANNEL, dominio |
| 10 | Continuita | Stato servizio, evidenza backup, procedure documentate |

## Parametri comuni

`-PercorsoUscita` (obbligatorio, deve già esistere), `-Formato` (`JSON`|`CSV`),
`-Verboso`, `-ConfigCA` ("Server\NomeCA", per interrogare una CA diversa da
quella locale — dove non pertinente per natura dell'accertamento, es. 09, il
parametro non è presente). Il programma 05 aggiunge inoltre `-LimiteRecord`,
`-DimensionePagina`, `-TuttiIRecord`, `-DataInizio`, `-DataFine`,
`-GiorniFinestraPredefinita`, `-StrategiaCampionamento`.

## Uscita

Ogni programma scrive `Evidenza_<NN>_<Nome>.<json|csv>` (record normalizzati:
`IdControllo, Dominio, Accertamento, Valore, Stato, DataOra, NomeHost,
Completezza, StrategiaLettura`) e `Riepilogo_<NN>_<Nome>.json` (accertamenti
tentati/riusciti/falliti, tempi). Il programma 05 scrive in aggiunta
`Dettaglio_05_CertificatiEmessi` con l'elenco analizzato.

`Stato` vale `rilevato`, `non applicabile` o `non verificabile` — **nessun
programma esprime un giudizio di conformità**: la valutazione avviene a valle,
sui dati raccolti qui.

## Limiti noti e accertamenti non automatizzabili

- **Policy di audit dettagliata del sistema operativo** (08) e
  **sincronizzazione oraria effettiva** (08): richiederebbero `auditpol.exe`
  e `w32tm.exe`, binari esterni non-PowerShell esclusi da questa raccolta.
  Dichiarati "non verificabile" con indicazione di verifica manuale.
- **Procedure documentate di continuità/disaster recovery** (10): non
  osservabile automaticamente per natura. Dichiarato "da verificare tramite
  intervista o ispezione manuale".
- **`EnforceX500NameLengths`** (02): percorso di registro non documentato con
  certezza univoca; il programma prova due posizioni note e dichiara "non
  verificabile" se nessuna risponde.
- **Formato testuale di `certutil -view`**: il parsing (programma 05, e in
  parte 06) si basa sul comportamento CSV comunemente noto di
  `-out`+`-restrict`, interpretato per posizione di colonna e non per nome di
  intestazione, proprio per non dipendere da un formato non garantito
  identico su ogni versione. **Il toolkit non è mai stato eseguito contro una
  CA Windows reale** (sviluppato in un ambiente Linux senza accesso a un
  server ADCS): un primo run reale su una CA di test è fortemente
  raccomandato prima dell'uso in produzione, per calibrare/confermare questo
  parsing.
- Non vengono usati oggetti COM `CertificateAuthority.View` (parametri
  numerici interni non documentati con certezza sufficiente); si usa invece
  `CertificateAuthority.Admin.GetCASecurity` (04/07), scelto perché non
  richiede parametri numerici ambigui.
