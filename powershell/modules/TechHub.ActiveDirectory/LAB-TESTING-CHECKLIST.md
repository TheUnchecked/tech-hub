# Checklist di validazione in laboratorio

Elenco completo di tutti i test da eseguire contro un dominio AD e computer
Windows reali, per validare `TechHub.ActiveDirectory` prima di usarlo in un
assessment vero. Ogni riga ha: comando esatto, a cosa serve, risultato
atteso, e che tipo di output/report produce.

Sostituisci `dc01.example.test`, `srv01`, `web01` ecc. con i nomi reali del
tuo laboratorio. Segna ogni casella mentre procedi.

---

## 0. Prerequisiti e setup

- [ ] **PowerShell 5.1 (Desktop), non 7/Core** — verifica con `$PSVersionTable.PSEdition` (deve dare `Desktop`).
- [ ] **RSAT Active Directory installato** — `Import-Module ActiveDirectory` non deve dare errore.
- [ ] **Branch corretto**: `git checkout worktree-fix-ad-assessment-issues` (o la PR mergiata su `main`, se nel frattempo l'hai fatto).
- [ ] **Permessi**: un utente con lettura su tutto il dominio (Domain Users basta per la maggior parte dei check; per `AD-DCSYNC-RIGHTS`/`AD-SHADOW-ADMIN` serve poter leggere `nTSecurityDescriptor` sulla radice del dominio e su AdminSDHolder, di norma già leggibile da un utente autenticato qualsiasi).
- [ ] **Connettività verso i target remoti**: WinRM (`Test-WSMan -ComputerName srv01`) e/o DCOM/RPC raggiungibili per almeno un paio di server del laboratorio.

```powershell
Import-Module .\TechHub.ActiveDirectory.psd1 -Force -Verbose
Get-Command -Module TechHub.ActiveDirectory | Measure-Object | Select-Object -ExpandProperty Count
```
**A cosa serve**: verifica che il modulo si carichi senza errori.
**Risultato atteso**: nessun errore, `39` funzioni esportate.
**Output**: nessun report, solo verifica tecnica.

---

## 1. Livello 1 — Assessment completo (il test più importante)

- [ ] **Full assessment end-to-end**
```powershell
$Result = Invoke-AssessmentADFullAssessment -Server dc01.example.test -Verbose
$Result.ReportPath
$Result.Assessment.Summary
```
**A cosa serve**: è IL test che convalida tutto insieme — 20 check di sicurezza AD + raccolta dati da tutti i server scoperti nel dominio.
**Risultato atteso**: nessuna eccezione non gestita; `$Result.ReportPath` punta a un file `.html` esistente; `$Result.Assessment.Summary` mostra conteggi coerenti (FindingsCount, SeverityCounts, ecc.).
**Report**: un file HTML unico con sezione "Security Findings" (i 20 check) + sezione "Inventory" (dati raccolti da ogni server).

- [ ] **Variante: solo check AD, senza toccare macchine remote**
```powershell
Invoke-AssessmentADFullAssessment -Server dc01.example.test -SkipRemoteAssessment -OutputPath .\report-ad-only.html
```
**A cosa serve**: isola eventuali problemi di connettività remota da quelli dei check AD.
**Risultato atteso**: report HTML solo con "Security Findings", nessuna sezione Inventory popolata.

- [ ] **Variante: computer specifici invece della discovery automatica**
```powershell
Invoke-AssessmentADFullAssessment -Server dc01.example.test -ComputerName 'srv01','srv02' -OutputPath .\report-2srv.html
```
**A cosa serve**: verifica che il bypass della discovery funzioni ed elabori solo i computer indicati.
**Risultato atteso**: sezione Inventory del report contiene solo dati di `srv01` e `srv02`.

---

## 2. Livello 2 — Ogni singolo check di sicurezza AD (20 check)

Per ciascuno: comando diretto (bypassa il registry, più comodo per il debug mirato).

### 2.1 Delegation

- [ ] **AD-UNCONSTRAINED-DELEGATION**
```powershell
Get-AssessmentADUnconstrainedDelegation -Server dc01.example.test -Verbose
```
A cosa serve: rileva account con delega Kerberos non vincolata (`TRUSTED_FOR_DELEGATION`).
Risultato atteso: un Finding per ogni account/computer con il flag; `Severity High` se abilitato, `Medium` se disabilitato. Se il dominio non ne ha, array vuoto (nessun errore).
Output: oggetti Finding Contract v1 (non un report a sé; confluiscono nel report di `Invoke-AssessmentADAssessment`).

- [ ] **AD-CONSTRAINED-DELEGATION**
```powershell
Get-AssessmentADConstrainedDelegation -Server dc01.example.test -Verbose
```
A cosa serve: rileva delega vincolata (`msDS-AllowedToDelegateTo`).
Risultato atteso: un Finding per account con delega configurata; severità in base a pattern (`-CriticalServicePatterns`) e numero di destinazioni.

- [ ] **AD-RBCD**
```powershell
Get-AssessmentADRBCD -Server dc01.example.test -Verbose
```
A cosa serve: rileva Resource-Based Constrained Delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`).
Risultato atteso: un Finding per ogni computer/servizio con RBCD configurato verso di esso.

### 2.2 Kerberos

- [ ] **AD-KERBEROASTING**
```powershell
Get-AssessmentADKerberoasting -Server dc01.example.test -Verbose
```
A cosa serve: trova account con SPN attaccabili via Kerberoasting.
Risultato atteso: un Finding per account con SPN; `Critical` se privilegiato (adminCount=1) e senza AES, `Low` se ordinario con AES. **Verifica manuale consigliata**: crea un account di test con SPN e password debole, conferma che compaia.

- [ ] **AD-ASREP-ROASTING**
```powershell
Get-AssessmentADASREPRoasting -Server dc01.example.test -Verbose
```
A cosa serve: trova account con `DONT_REQUIRE_PREAUTH`.
Risultato atteso: se non hai account così configurati, array vuoto. **Verifica manuale consigliata**: su un account di test, abilita "Do not require Kerberos preauthentication" e conferma che compaia con `Severity High` (o `Critical` se privilegiato).

- [ ] **AD-KRBTGT-PASSWORD-AGE**
```powershell
Get-AssessmentADKrbtgtPasswordAge -Server dc01.example.test -Verbose
Get-AssessmentADKrbtgtPasswordAge -Server dc01.example.test -MaxPasswordAgeDays 30 -Verbose
```
A cosa serve: età password dell'account krbtgt.
Risultato atteso: sempre esattamente **1** Finding. Con `-MaxPasswordAgeDays 30` la severità dovrebbe salire (quasi certamente `High` o `Critical` a meno che tu non abbia appena ruotato la password krbtgt).

### 2.3 Authentication

- [ ] **AD-PASSWORD-POLICY**
```powershell
Get-AssessmentADPasswordPolicy -Server dc01.example.test -Verbose
Get-AssessmentADPasswordPolicy -Server dc01.example.test -IncludeFineGrainedPolicies -Verbose
```
A cosa serve: valuta la password policy di dominio (e, con `-IncludeFineGrainedPolicies`, le eventuali PSO).
Risultato atteso: senza il flag, **1** Finding (default domain policy). Con il flag, 1 + N (una per ogni PSO esistente, 0 se non ne hai configurate).

### 2.4 PrivilegedAccess

- [ ] **AD-DCSYNC-RIGHTS**
```powershell
Get-AssessmentADDCSyncRights -Server dc01.example.test -Verbose
```
A cosa serve: trova chi ha i diritti di replica (DCSync) fuori dai detentori di default.
Risultato atteso: in un dominio "pulito", array vuoto (Domain Admins/Enterprise Admins/SYSTEM sono esclusi di default). **Verifica manuale consigliata**: concedi temporaneamente `Replicating Directory Changes` + `...All` a un utente di test sulla radice del dominio, conferma `Severity Critical`, poi **rimuovi il permesso**.

- [ ] **AD-SHADOW-ADMIN**
```powershell
Get-AssessmentADShadowAdminRights -Server dc01.example.test -Verbose
```
A cosa serve: trova chi ha `GenericAll`/`WriteDacl`/`WriteOwner`/`GenericWrite` su domain root o AdminSDHolder fuori dai detentori attesi.
Risultato atteso: array vuoto in un dominio pulito. Stessa nota di verifica manuale del punto precedente (concedi/revoca un permesso di test).

- [ ] **AD-PRIVILEGED-GROUP**
```powershell
Get-AssessmentADPrivilegedGroup -Server dc01.example.test -Verbose
```
A cosa serve: analizza i membri dei gruppi privilegiati.
Risultato atteso: un Finding per ogni membro dei gruppi configurati (default: i gruppi built-in principali).
⚠️ Questo check ha una correzione in corso su un branch separato (`fix/ad-privileged-group-server-context`, non incluso in questa PR) — se noti anomalie sulla risoluzione di membership annidata/cicli, **non è un problema di questa PR**, segnalamelo comunque separatamente.

- [ ] **AD-REMOTE-LOCAL-GROUPS**
```powershell
$Provider = New-AssessmentADProvider -Server dc01.example.test
Invoke-AssessmentADRemoteLocalGroups -Provider $Provider -TargetType Server -Verbose
```
A cosa serve: gruppi locali su tutti i server scoperti in AD.
Risultato atteso: un record per ogni gruppo locale trovato su ogni server raggiungibile; per i server non raggiungibili, record con `Status = 'NotAvailable'` invece di un'eccezione.

### 2.5 AccountHygiene

- [ ] **AD-STALE-ACCOUNTS**
```powershell
Get-AssessmentADStaleAccounts -Server dc01.example.test -StaleDays 90 -Verbose
```
A cosa serve: account abilitati senza logon da oltre la soglia.
Risultato atteso: dipende dal tuo laboratorio; con `-StaleDays 0` dovresti ottenere quasi tutti gli account (buon modo per verificare che il check "funzioni" anche se il tuo lab è nuovo/pulito).
```powershell
Get-AssessmentADStaleAccounts -Server dc01.example.test -StaleDays 0 -Verbose
```

- [ ] **AD-PASSWORD-NEVER-EXPIRES**
```powershell
Get-AssessmentADPasswordNeverExpiresAccounts -Server dc01.example.test -Verbose
```
A cosa serve: account con password che non scade mai.
Risultato atteso: `krbtgt` e account di default con questa impostazione dovrebbero comparire (`krbtgt` in particolare ha sempre questo flag, verifica che compaia con severità coerente).

### 2.6 Hardening

- [ ] **AD-PROTECTED-USERS-COVERAGE**
```powershell
Get-AssessmentADProtectedUsersCoverage -Server dc01.example.test -Verbose
```
A cosa serve: membri di Domain Admins/Enterprise Admins non coperti da Protected Users.
Risultato atteso: quasi certamente **non vuoto** nella maggior parte dei laboratori (Protected Users è raramente popolato di default) — è normale, non un bug.

- [ ] **AD-AUTH-HARDENING**
```powershell
Get-AssessmentADRemoteAuthenticationHardening -Server dc01.example.test -Verbose
Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01.example.test' -Verbose
```
A cosa serve: legge `LmCompatibilityLevel`/`NoLmHash`/`LDAPServerIntegrity` da remoto via CIM.
Risultato atteso: la prima riga scopre i DC automaticamente e produce 1 Finding per DC; la seconda mostra lo stesso risultato per un target esplicito. **Da controllare con `-Verbose`**: quale trasporto è stato usato (WSMan o DCOM).

- [ ] **AD-CREDENTIAL-GUARD**
```powershell
Get-AssessmentADRemoteCredentialGuardStatus -Server dc01.example.test -Verbose
```
A cosa serve: verifica se Credential Guard è attivo sui DC.
Risultato atteso: se il DC è una VM senza virtualizzazione annidata attiva, aspettati `Severity Medium` (VBS non attivo) — normale in molti laboratori, non un bug del check.

- [ ] **AD-OBSOLETE-OS**
```powershell
Get-AssessmentADRemoteObsoleteOperatingSystem -Server dc01.example.test -TargetType All -Verbose
```
A cosa serve: segnala OS oltre l'end-of-support.
Risultato atteso: un Finding per ogni computer scoperto (`Severity High` solo per quelli che matchano i pattern obsoleti, `Informational` per gli altri — quindi aspettati **sempre** un numero di Finding pari al numero di computer, non solo per quelli vecchi).

### 2.7 AuditingAndLogging

- [ ] **AD-AUDIT-POLICY**
```powershell
Get-AssessmentADRemoteAuditPolicy -Server dc01.example.test -Verbose
```
A cosa serve: verifica se le sottocategorie di audit di sicurezza sono abilitate sui DC.
Risultato atteso: 1 Finding per DC. **Questo è il check con il rischio maggiore di comportarsi diversamente dal previsto** (parsing CSV di `auditpol /get /r`, sensibile a lingua/versione OS) — se ottieni un errore di parsing o valori inattesi, è la prima cosa da segnalarmi con l'output completo di `-Verbose`.

### 2.8 DNS

- [ ] **AD-DNS-ZONE-SECURITY**
```powershell
Get-AssessmentADDNSZoneSecurity -Server dc01.example.test -Verbose
```
A cosa serve: valuta dynamic update e zone transfer sulle zone DNS AD-integrated.
Risultato atteso: dipende se il DC target ha il ruolo DNS + modulo `DnsServer` installato.
  - Se **non disponibile**: `Status = 'NotAvailable'`, `ErrorType = 'ModuleUnavailable'` — comportamento atteso e corretto, non un errore.
  - Se **disponibile**: 1 Finding per zona AD-integrated primaria.
```powershell
Get-Module -ListAvailable -Name DnsServer   # esegui PRIMA per sapere cosa aspettarti
```

### 2.9 DisasterRecovery

- [ ] **AD-RECYCLE-BIN**
```powershell
Get-AssessmentADRecycleBinStatus -Server dc01.example.test -Verbose
```
A cosa serve: verifica se il Recycle Bin di AD è abilitato.
Risultato atteso: 1 Finding. Molti laboratori di test hanno il Recycle Bin **disabilitato** di default — aspettati `Severity Medium`, è normale.

---

## 3. Livello 2b — Il motore/registry (esegue i check sopra in blocco)

- [ ] **Tutti i 20 check in un colpo**
```powershell
$Registry = New-AssessmentADCheckRegistry
$Registry.GetAll() | Format-Table CheckId, Name, Category, Enabled -AutoSize

$Assessment = Invoke-AssessmentADAssessment -Server dc01.example.test -Verbose
$Assessment.Metadata.CheckResults | Format-Table CheckId, Status, ErrorType -AutoSize
```
A cosa serve: verifica che il motore selezioni ed esegua tutti i 20 check senza saltarne nessuno.
Risultato atteso: `$Registry.GetAll().Count` = 20; in `CheckResults`, ogni CheckId compare con `Status` = `Available`/`Partial` (mai un'eccezione che ferma l'intero assessment).

- [ ] **Filtro per categoria**
```powershell
Invoke-AssessmentADAssessment -Server dc01.example.test -Category 'Hardening' -Verbose
```
Risultato atteso: solo i 4 check Hardening vengono eseguiti.

- [ ] **Filtro per singolo CheckId**
```powershell
Invoke-AssessmentADAssessment -Server dc01.example.test -CheckId 'AD-DNS-ZONE-SECURITY' -Verbose
```
Risultato atteso: solo quel check viene eseguito.

---

## 4. Livello 3 — Collector di infrastruttura remota (standalone)

Da testare su almeno un server membro (`srv01`) e, se disponibile, un server IIS (`web01`).

- [ ] `Get-AssessmentADRemoteOSInfo -ComputerName 'srv01' -Verbose` — OS/versione/build. Atteso: `Status = 'Available'`, `CollectionMethod` = WinRM o WMI.
- [ ] `Get-AssessmentADRemoteWindowsFeatures -ComputerName 'srv01' -Verbose` — feature Windows installate.
- [ ] `Get-AssessmentADRemoteLocalGroupMembers -ComputerName 'srv01' -Verbose` — membri dei gruppi locali.
- [ ] `Get-AssessmentADRemoteLocalGroups -ComputerName 'srv01','srv02' -Verbose` — elenco gruppi locali (senza membri) su più computer.
- [ ] `Get-AssessmentADRemoteNetworkShareACLs -ComputerName 'srv01' -Verbose` — condivisioni e ACL.
- [ ] `Get-AssessmentADRemoteScheduledTaskAccounts -ComputerName 'srv01' -Verbose` — account "run as" degli scheduled task.
- [ ] `Get-AssessmentADRemoteIISAppPoolAccounts -ComputerName 'web01' -Verbose` — account identity dei pool IIS (richiede un server con IIS).
- [ ] `Get-AssessmentADServiceAccounts -ComputerName 'srv01' -Verbose` — account di servizio aggregati (servizi + scheduled task + IIS).
- [ ] `Get-AssessmentADRemoteTargets -Provider $Provider -TargetType All -Verbose` — discovery di tutti i computer del dominio.
- [ ] `Invoke-AssessmentADRemoteAssessment -ComputerName 'srv01' -Verbose` — tutti e 7 i collector sopra in un colpo solo su un computer.

**A cosa servono nel complesso**: alimentano la sezione "Inventory" del report quando usati tramite `Invoke-AssessmentADFullAssessment`/`Invoke-AssessmentADRemoteAssessment`; presi singolarmente servono per debug mirato di un singolo dato.
**Risultato atteso comune**: mai un'eccezione non gestita — un server irraggiungibile deve produrre un record con `Status = 'NotAvailable'`, non un crash.

- [ ] **Test esplicito di errore**: punta a un computer che NON esiste, per verificare la gestione errori.
```powershell
Get-AssessmentADRemoteOSInfo -ComputerName 'computer-che-non-esiste-123' -Verbose
```
Risultato atteso: nessuna eccezione visibile all'utente; oggetto con `Status = 'NotAvailable'` ed `ErrorMessage` popolato.

---

## 5. Provider — capability dirette (facoltativo, per debug approfondito)

```powershell
$Provider = New-AssessmentADProvider -Server dc01.example.test

$Provider.GetDomainInformation().Status          # Available
$Provider.GetForestInformation().Status          # Available
$Provider.GetDomainControllers().Data.Count      # > 0
$Provider.GetGroups('Name -like "*Admin*"', $null).Data | Select Name
$Provider.GetGroupMembers('Domain Admins').Data | Select Name, SID
$Provider.GetDefaultDomainPasswordPolicy().Data
$Provider.GetFineGrainedPasswordPolicies().Data
$Provider.GetOptionalFeatures("Name -eq 'Recycle Bin Feature'").Data
$Provider.GetObjectSecurityDescriptor((Get-ADDomain).DistinguishedName).Data | Select IdentityReference, ActiveDirectoryRights -First 10
$Provider.GetDnsZones().Status                   # Available o NotAvailable a seconda del modulo DnsServer
$Provider.GetDnsZoneTransferSettings('example.test').Data
$Provider.GetProviderStatus()                    # riepilogo aggregato di tutte le operazioni fin qui
```
**A cosa serve**: isola un problema al livello "dati grezzi da AD" prima di sospettare la logica del check che li consuma.
**Risultato atteso**: ogni chiamata restituisce `Status = 'Available'` con `.Data` popolato (o `NotAvailable`/`Error` con `ErrorType` sensato, mai un'eccezione .NET grezza).

---

## 6. Esportazione report

```powershell
$Assessment = Invoke-AssessmentADAssessment -Server dc01.example.test

Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path .\report.html
Export-AssessmentADAssessmentJson -Assessment $Assessment -Path .\report.json
Export-AssessmentADAssessmentCsv  -Assessment $Assessment -Path .\report.csv
```
**A cosa servono**: tre formati per tre usi diversi — HTML per la lettura/presentazione, JSON per l'elaborazione automatica o l'archiviazione, CSV per aprire in Excel/analisi tabellare.
**Risultato atteso**: tre file creati senza errori; apri `report.html` in un browser e verifica che l'Executive Summary in cima mostri gli stessi numeri di `$Assessment.Summary`.

---

## 7. Riepilogo: cosa segnalarmi se qualcosa non va

Per ogni anomalia, questi 4 dati bastano quasi sempre per farmela correggere:

1. Il comando esatto lanciato (copia-incolla).
2. L'output completo (incluso `-Verbose` se possibile).
3. Cosa ti aspettavi (da questa checklist).
4. Versione OS del target e se è un Domain Controller o un server membro.
