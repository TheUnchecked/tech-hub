# TechHub.ActiveDirectory — Guida completa

Guida di riferimento a tutte le funzioni del modulo `TechHub.ActiveDirectory`,
pensata per chi deve provarlo in laboratorio o integrarlo in un assessment.
Per l'architettura interna (Provider, Registry, Engine) vedi anche
`README.md`, `Engine.README.md`, `Registry.README.md` e `Providers/README.md`
nella stessa cartella — questo documento li riassume e aggiunge la reference
di ogni funzione pubblica con parametri ed esempi.

---

## 1. Cos'è

Modulo PowerShell **read-only** per:

1. **AD Security Assessment** — delegazione Kerberos (unconstrained,
   constrained, RBCD), gruppi privilegiati, service account.
2. **Remote Infrastructure Assessment** — raccolta di configurazione da
   computer Windows (account di servizio, scheduled task, IIS app pool,
   gruppi locali, ACL delle share, OS info, feature installate).

Nessuna funzione modifica AD, esegue codice dinamico arbitrario, tenta
exploitation, dumping di credenziali o bypass. Non contiene e non richiede
credenziali salvate.

## 2. Requisiti

| Requisito | Note |
|---|---|
| Windows PowerShell **5.1** (Desktop) | Il manifest dichiara `CompatiblePSEditions = 'Desktop'`; non è pensato per PowerShell 7/Core |
| Modulo RSAT `ActiveDirectory` | Necessario per i check AD Security (non per i soli collector remoti) |
| Accesso in lettura agli oggetti AD interrogati | Nessun privilegio di scrittura richiesto |
| Permessi remoti adeguati | Per i collector remoti |
| Connettività di rete | WinRM/WS-Man, CIM/DCOM, RPC a seconda del collector |

## 3. Import

```powershell
Import-Module .\TechHub.ActiveDirectory.psd1 -Force
Get-Command -Module TechHub.ActiveDirectory
```

## 4. Architettura in breve

```
Registry  →  Engine (Invoke-AssessmentADAssessment)  →  AssessmentResult
   |                    |
   |                    +-- crea/riusa --> TechHubADProvider --> cmdlet AD reali
   |
   +-- metadata dei check (CheckId, categoria, IsReadOnly, provider richiesti)
```

- **Provider** (`New-AssessmentADProvider`) — unico punto di accesso ai
  cmdlet AD reali (`Get-ADDomain`, `Get-ADGroup`, `Get-ADObject`, ...).
- **Registry** (`New-AssessmentADCheckRegistry`) — elenco dichiarativo dei
  check disponibili, non esegue nulla.
- **Engine** (`Invoke-AssessmentADAssessment`) — seleziona i check abilitati
  dal registry, li esegue, isola i fallimenti, produce un
  `TechHubADAssessmentResult`.
- **Collector remoti** — funzioni indipendenti dal provider AD, usano CIM
  (WSMan con fallback DCOM) o WinRM per interrogare computer Windows.
- **Exporter** — serializzano un `AssessmentResult` in JSON, CSV o HTML.

---

## 5. Reference funzioni

### 5.1 Check di sicurezza Active Directory

Tutte richiedono il modulo `ActiveDirectory` e, se non passato esplicitamente
un `-Provider`, ne creano uno internamente con `-Server`.

#### `Get-AssessmentADUnconstrainedDelegation`
Rileva account con il flag `TRUSTED_FOR_DELEGATION` (`userAccountControl` `0x80000`).
```powershell
Get-AssessmentADUnconstrainedDelegation
Get-AssessmentADUnconstrainedDelegation -Server dc01.example.test -SearchBase 'OU=Servers,DC=example,DC=test'
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`, `-Provider`.

#### `Get-AssessmentADConstrainedDelegation`
Rileva delegazione vincolata tramite `msDS-AllowedToDelegateTo`.
```powershell
Get-AssessmentADConstrainedDelegation
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`,
`-CriticalServicePatterns`, `-DocumentedServicePatterns`, `-ExcludedServicePatterns`
(pattern personalizzabili per classificare i target di delegazione), `-Provider`.

#### `Get-AssessmentADRBCD`
Rileva Resource-Based Constrained Delegation tramite
`msDS-AllowedToActOnBehalfOfOtherIdentity`.
```powershell
Get-AssessmentADRBCD
```
Parametri: `-Server`, `-SearchBase`, `-SensitiveTargetPatterns`,
`-ApprovedIdentityPatterns`, `-ExcludedIdentityPatterns`.

#### `Get-AssessmentADPrivilegedGroup`
Analizza l'appartenenza ai gruppi privilegiati (Domain Admins, Enterprise
Admins, ecc.) e relativi indicatori di rischio.
```powershell
Get-AssessmentADPrivilegedGroup
Get-AssessmentADPrivilegedGroup -IncludeDisabled
```
Parametri: `-Server`, `-SearchBase`, `-GroupPatterns`, `-ApprovedMemberPatterns`,
`-ExcludedMemberPatterns`, `-PrivilegedGroupPatterns`, `-ServiceAccountPatterns`,
`-IncludeDisabled`.

> ⚠️ Al momento di questa guida, la risoluzione della membership annidata di
> questo check è oggetto di un fix separato non ancora mergiato
> (branch `fix/ad-privileged-group-server-context`). Se lo provi in lab,
> verifica di essere sul branch più aggiornato.

#### `Get-AssessmentADKerberoasting`
Rileva account utente con Service Principal Name (SPN), classificandoli per priorità: privilegiati (`adminCount=1`) e/o senza supporto AES (`msDS-SupportedEncryptionTypes`) sono più critici.
```powershell
Get-AssessmentADKerberoasting
Get-AssessmentADKerberoasting -ExcludedAccountPatterns 'svc-approved-*'
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`,
`-ExcludedAccountPatterns` (pattern SamAccountName da escludere), `-StalePasswordDays`, `-Provider`.

#### `Get-AssessmentADASREPRoasting`
Rileva account con `DONT_REQUIRE_PREAUTH` (`userAccountControl` `0x400000`): attaccabili offline senza credenziali valide.
```powershell
Get-AssessmentADASREPRoasting
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`,
`-ExcludedAccountPatterns`, `-Provider`.

#### `Get-AssessmentADKrbtgtPasswordAge`
Riporta l'età della password dell'account `krbtgt` (indicatore di esposizione a golden ticket).
```powershell
Get-AssessmentADKrbtgtPasswordAge
Get-AssessmentADKrbtgtPasswordAge -MaxPasswordAgeDays 90
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`, `-MaxPasswordAgeDays` (default 180), `-Provider`.

#### `Get-AssessmentADPasswordPolicy`
Valuta la password policy di default del dominio e, opzionalmente, le Fine-Grained Password Policy, contro una baseline (lunghezza minima, complessità, reversible encryption, lockout).
```powershell
Get-AssessmentADPasswordPolicy
Get-AssessmentADPasswordPolicy -IncludeFineGrainedPolicies -MinPasswordLengthThreshold 14
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`,
`-MinPasswordLengthThreshold` (default 14), `-IncludeFineGrainedPolicies`, `-Provider`.

#### `Get-AssessmentADDCSyncRights`
Analizza l'ACL sulla radice del dominio per individuare principal (fuori dai detentori di default: Domain Admins, Enterprise Admins, Domain Controllers, SYSTEM, ecc.) con i diritti di replica `DS-Replication-Get-Changes`/`-All` (DCSync).
```powershell
Get-AssessmentADDCSyncRights
Get-AssessmentADDCSyncRights -ApprovedPrincipalPatterns '*\Domain Admins', '*\svc-adconnect'
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`,
`-ApprovedPrincipalPatterns`, `-Provider`.

#### `Get-AssessmentADShadowAdminRights`
Analizza l'ACL sulla radice del dominio e su `AdminSDHolder` per individuare principal con diritti `GenericAll`/`WriteDacl`/`WriteOwner`/`GenericWrite` fuori dai detentori di default ("shadow admin").
```powershell
Get-AssessmentADShadowAdminRights
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`,
`-ApprovedPrincipalPatterns`, `-Provider`.

> Queste due funzioni usano una nuova capability del Provider,
> `GetObjectSecurityDescriptor($Identity)`, che legge (mai scrive)
> l'attributo `nTSecurityDescriptor` tramite `Get-ADObject`.

#### `Get-AssessmentADStaleAccounts`
Account utente/computer abilitati che non fanno logon da oltre una soglia configurabile (`lastLogonTimestamp`). Un account privilegiato stale è severità High, gli altri Medium.
```powershell
Get-AssessmentADStaleAccounts
Get-AssessmentADStaleAccounts -StaleDays 180
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`,
`-StaleDays` (default 90), `-ExcludedAccountPatterns`, `-Provider`.

#### `Get-AssessmentADPasswordNeverExpiresAccounts`
Account con password che non scade mai (`DONT_EXPIRE_PASSWORD`).
```powershell
Get-AssessmentADPasswordNeverExpiresAccounts
```
Parametri: `-Server`, `-SearchBase`, `-Domain`, `-Forest`, `-DomainController`,
`-ExcludedAccountPatterns`, `-Provider`.

#### `Get-AssessmentADProtectedUsersCoverage`
Membri di gruppi privilegiati (default: Domain Admins, Enterprise Admins) che non sono anche membri di `Protected Users`.
```powershell
Get-AssessmentADProtectedUsersCoverage
Get-AssessmentADProtectedUsersCoverage -PrivilegedGroups 'Domain Admins', 'Tier0-Operators'
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`,
`-PrivilegedGroups` (default `Domain Admins`, `Enterprise Admins`),
`-ProtectedUsersGroupName` (default `Protected Users`), `-Provider`.

#### `Get-AssessmentADRemoteAuthenticationHardening`
Legge da remoto (via CIM, nessun PowerShell remoting) `LmCompatibilityLevel`, `NoLmHash` e (sui DC) `LDAPServerIntegrity`. Senza `-ComputerName`, scopre i domain controller automaticamente.
```powershell
Get-AssessmentADRemoteAuthenticationHardening
Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01','dc02'
```
Parametri: `-ComputerName`, `-TargetType` (default `DomainController`),
`-Credential`, `-UseSSL`, `-Server`, `-Provider`.

#### `Get-AssessmentADRemoteCredentialGuardStatus`
Verifica se virtualization-based security e Credential Guard sono attivi (CIM, classe `Win32_DeviceGuard`).
```powershell
Get-AssessmentADRemoteCredentialGuardStatus
```
Parametri: `-ComputerName`, `-TargetType` (default `DomainController`),
`-Credential`, `-UseSSL`, `-Server`, `-Provider`.

#### `Get-AssessmentADRemoteObsoleteOperatingSystem`
Segnala computer con OS oltre l'end-of-support (riusa `Get-AssessmentADRemoteOSInfo`).
```powershell
Get-AssessmentADRemoteObsoleteOperatingSystem -TargetType All
```
Parametri: `-ComputerName`, `-TargetType` (default `All`),
`-ObsoleteOSPatterns` (default: XP/Vista/7/8/Server 2003/2008/2012),
`-Credential`, `-UseSSL`, `-Server`, `-Provider`.

#### `Get-AssessmentADRemoteAuditPolicy`
Esegue `auditpol /get` via WinRM e segnala le sottocategorie di sicurezza (Directory Service, Kerberos, Logon/Logoff, Credential Validation) impostate su "No Auditing".
```powershell
Get-AssessmentADRemoteAuditPolicy
```
Parametri: `-ComputerName`, `-TargetType` (default `DomainController`),
`-AuditedSubcategories`, `-Credential`, `-Server`, `-Provider`.

#### `Get-AssessmentADDNSZoneSecurity`
Valuta le zone DNS AD-integrated: `DynamicUpdate` (flag se `NonsecureAndSecure`) e trasferimento di zona (flag se `TransferAnyServer`).

> ⚠️ **Unica funzione del modulo che richiede il modulo `DnsServer`**, oltre ad `ActiveDirectory` — tipicamente disponibile solo su un DC che ospita anche il ruolo DNS. Se il modulo non è disponibile, il check ritorna `NotAvailable` in modo pulito (stesso pattern usato per `ActiveDirectory`).

```powershell
Get-AssessmentADDNSZoneSecurity
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`, `-Provider`.

#### `Get-AssessmentADRecycleBinStatus`
Verifica se la funzionalità AD Recycle Bin è abilitata (`Get-ADOptionalFeature`).
```powershell
Get-AssessmentADRecycleBinStatus
```
Parametri: `-Server`, `-Domain`, `-Forest`, `-DomainController`, `-Provider`.

#### `Get-AssessmentADInventory`
Inventario read-only di utenti, computer, gruppi, MSA/gMSA e OU, tramite il
provider (nessun cmdlet AD invocato direttamente).
```powershell
Get-AssessmentADInventory -Provider (New-AssessmentADProvider -Server dc01.example.test)
```
Parametri: `-Provider`, `-Server`, `-SearchBase`.

#### `Get-AssessmentADServiceAccounts`
Inventaria gli account usati da servizi Windows, scheduled task e IIS app
pool su una o più macchine remote, normalizzando i tre meccanismi in un
contratto comune.
```powershell
Get-AssessmentADServiceAccounts -ComputerName 'srv01','srv02'
```
Parametri: `-ComputerName` (`string[]`, mandatory), `-Credential`.

---

### 5.2 Collector di infrastruttura remota

Funzioni generiche, non legate al Tier Model, utilizzabili anche in un
assessment infrastrutturale generico. Tre di queste (`Get-AssessmentADRemoteOSInfo`,
`Get-AssessmentADRemoteWindowsFeatures`, `Get-AssessmentADRemoteLocalGroupMembers`)
usano l'helper condiviso `Invoke-AssessmentADRemoteCimQuery`
(CIM/WSMan con fallback CIM/DCOM) — è l'helper che era mancante e che è stato
aggiunto in questo branch.

> Nota sull'invocazione: alcune funzioni accettano `-ComputerName` come
> stringa singola (pensate per la pipeline, una chiamata per host), altre
> come array (`string[]`, una sola chiamata per più host). Vedi la tabella
> dei parametri di ciascuna.

#### `Get-AssessmentADRemoteOSInfo`
Raccoglie OS, versione, build e classificazione `ProductType`
(1=Client, 2=DomainController, 3=Server).
```powershell
Get-AssessmentADRemoteOSInfo -ComputerName 'srv01'
'srv01','srv02' | Get-AssessmentADRemoteOSInfo
Get-AssessmentADRemoteOSInfo -ComputerName 'srv01' -UseSSL
```
Parametri: `-ComputerName` (`string`, mandatory, pipeline), `-Credential`, `-UseSSL`.

#### `Get-AssessmentADRemoteWindowsFeatures`
Feature Windows installate. Prova prima WinRM (`Invoke-Command` +
`Get-WindowsFeature`/`Get-WindowsOptionalFeature`), poi CIM/DCOM
(`Win32_OptionalFeature`) come fallback.
```powershell
Get-AssessmentADRemoteWindowsFeatures -ComputerName 'srv01','srv02'
```
Parametri: `-ComputerName` (`string[]`, mandatory, pipeline), `-Credential`, `-UseSSL`.

#### `Get-AssessmentADRemoteLocalGroupMembers`
Appartenenza ai gruppi locali (Win32_Group/Win32_GroupUser), preservando
dominio, SID, tipo di account. Non classifica i membri: solo raccolta e
normalizzazione.
```powershell
Get-AssessmentADRemoteLocalGroupMembers -ComputerName 'srv01'
```
Parametri: `-ComputerName` (`string`, mandatory, pipeline), `-Credential`, `-UseSSL`.

#### `Get-AssessmentADRemoteLocalGroups`
Variante che elenca i gruppi locali (non i membri) su uno o più computer.
```powershell
Get-AssessmentADRemoteLocalGroups -ComputerName 'srv01','srv02'
```
Parametri: `-ComputerName` (`string[]`, mandatory), `-Credential`.

#### `Get-AssessmentADRemoteNetworkShareACLs`
Share SMB e relative ACL. Usa `Get-SmbShare`/`Get-SmbShareAccess` quando
disponibili, altrimenti fallback su classi CIM `Win32_Share*`.
```powershell
Get-AssessmentADRemoteNetworkShareACLs -ComputerName 'srv01'
Get-AssessmentADRemoteNetworkShareACLs -ComputerName 'srv01' -IncludeAdminShares
```
Parametri: `-ComputerName` (`string`, mandatory), `-IncludeAdminShares`, `-Credential`.

#### `Get-AssessmentADRemoteScheduledTaskAccounts`
Account "run as" degli scheduled task. Prova CIM (`Get-ScheduledTask
-CimSession`), poi fallback sull'API COM Task Scheduler.
```powershell
Get-AssessmentADRemoteScheduledTaskAccounts -ComputerName 'srv01'
```
Parametri: `-ComputerName` (`string`, mandatory).

#### `Get-AssessmentADRemoteIISAppPoolAccounts`
Account identity dei pool applicativi IIS.
```powershell
Get-AssessmentADRemoteIISAppPoolAccounts -ComputerName 'web01'
```
Parametri: `-ComputerName` (`string`, mandatory).

#### `Get-AssessmentADRemoteTargets`
Scopre computer da Active Directory e, se richiesto, li classifica
interrogandone l'OS reale (via `Get-AssessmentADRemoteOSInfo`, WinRM con
fallback WMI/DCOM). Con `-TargetType All` non serve connessione remota.
```powershell
Get-AssessmentADRemoteTargets -Provider $Provider -TargetType All
Get-AssessmentADRemoteTargets -Provider $Provider -TargetType Server -SearchBase 'OU=Servers,DC=example,DC=test'
```
Parametri: `-Provider` (mandatory), `-TargetType` (`All`/`Server`/`Client`/`DomainController`),
`-SearchBase`, `-IncludeDisabled`.

#### `Invoke-AssessmentADRemoteLocalGroups`
Orchestratore: scopre i target con `Get-AssessmentADRemoteTargets` e
raccoglie i gruppi locali con `Get-AssessmentADRemoteLocalGroupMembers` per
ciascuno, senza filtri hardcoded sugli account.
```powershell
Invoke-AssessmentADRemoteLocalGroups -Provider $Provider -TargetType Server
Invoke-AssessmentADRemoteLocalGroups -Provider $Provider -ComputerName 'srv01','srv02'
```
Parametri: `-Provider` (mandatory), `-TargetType`, `-SearchBase`, `-IncludeDisabled`, `-ComputerName`.

#### `Invoke-AssessmentADRemoteAssessment`
Orchestratore generico dei collector remoti su un singolo computer;
`-Collector` seleziona quali eseguire.
```powershell
Invoke-AssessmentADRemoteAssessment -ComputerName 'srv01'
Invoke-AssessmentADRemoteAssessment -ComputerName 'srv01' -Collector 'OSInfo','WindowsFeatures'
```
Parametri: `-ComputerName` (mandatory), `-Assessment`, `-Collector`.

#### `Invoke-AssessmentADFullAssessment`
Comando unico: esegue l'assessment di sicurezza AD, scopre (o usa la lista
fornita di) computer remoti, raccoglie i dati infrastrutturali da ciascuno e
esporta **un solo report HTML** con dentro tutto. È la funzione da usare per
"lanciare un assessment completo" con un comando solo.
```powershell
# Tutto in automatico: scopre i server del dominio ed esporta un report con timestamp
Invoke-AssessmentADFullAssessment -Server dc01.example.test

# Lista di computer esplicita e path di output scelto
Invoke-AssessmentADFullAssessment -Server dc01.example.test -ComputerName 'srv01','srv02' -OutputPath .\report.html

# Solo i check di sicurezza AD, senza contattare macchine remote
Invoke-AssessmentADFullAssessment -Server dc01.example.test -SkipRemoteAssessment
```
Parametri: `-Server`, `-TargetType` (default `Server`, usato per la discovery
automatica quando non passi `-ComputerName`), `-ComputerName`,
`-SkipRemoteAssessment`, `-OutputPath` (default: file con timestamp nella
directory corrente), `-Provider`.

Restituisce un oggetto con `.Assessment` (l'oggetto assessment completo,
utile per ulteriori export JSON/CSV) e `.ReportPath` (il percorso del file
HTML scritto).

---

### 5.3 Provider

#### `New-AssessmentADProvider`
Crea un `TechHubADProvider`: unico punto d'accesso ai cmdlet AD read-only
(`Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`, `Get-ADObject`,
`Get-ADGroup`, `Get-ADGroupMember`). Non modifica AD, non esegue codice
dinamico, non accetta scriptblock.
```powershell
$Provider = New-AssessmentADProvider -Server dc01.example.test
```
Parametro: `-Server` (opzionale — se omesso, autodiscovery del dominio corrente).

---

### 5.4 Registry e Engine

#### `New-AssessmentADCheckRegistry`
Costruisce il registro dei check disponibili (metadata: `CheckId`, `Name`,
`Category`, `Enabled`, `FunctionName`, `RequiredProviders`, `IsReadOnly`).
Non esegue nulla.
```powershell
$Registry = New-AssessmentADCheckRegistry
$Registry.GetAll() | Format-Table CheckId, Name, Category, Enabled
```
Check attualmente registrati (20): `AD-UNCONSTRAINED-DELEGATION`,
`AD-CONSTRAINED-DELEGATION`, `AD-RBCD`, `AD-KERBEROASTING`,
`AD-ASREP-ROASTING`, `AD-KRBTGT-PASSWORD-AGE`, `AD-PASSWORD-POLICY`,
`AD-DCSYNC-RIGHTS`, `AD-SHADOW-ADMIN`, `AD-PRIVILEGED-GROUP`,
`AD-REMOTE-LOCAL-GROUPS`, `AD-STALE-ACCOUNTS`, `AD-PASSWORD-NEVER-EXPIRES`,
`AD-PROTECTED-USERS-COVERAGE`, `AD-AUTH-HARDENING`, `AD-CREDENTIAL-GUARD`,
`AD-OBSOLETE-OS`, `AD-AUDIT-POLICY`, `AD-DNS-ZONE-SECURITY`,
`AD-RECYCLE-BIN`.

Categorie: `Delegation`, `Kerberos`, `Authentication`, `PrivilegedAccess`,
`AccountHygiene`, `Hardening`, `AuditingAndLogging`, `DNS`,
`DisasterRecovery`. L'area Group Policy (delega GPO, GPP password cache,
igiene OU) è **esclusa per scelta** da questo registro.

#### `Invoke-AssessmentADAssessment`
Motore di orchestrazione: seleziona i check abilitati dal registry (con
filtro opzionale `-CheckId`/`-Category`), risolve la funzione con
`Get-Command`, la esegue, isola i fallimenti per singolo check e restituisce
un `TechHubADAssessmentResult` completo di metadata e riepilogo.
```powershell
# Assessment completo
Invoke-AssessmentADAssessment

# Solo un check
Invoke-AssessmentADAssessment -CheckId 'AD-RBCD'

# Solo una categoria
Invoke-AssessmentADAssessment -Category 'Delegation'

# Con server e provider espliciti
Invoke-AssessmentADAssessment -Server dc01.example.test -Provider $Provider
```
Parametri: `-Registry`, `-CheckId`, `-Category`, `-Provider`, `-Server`,
`-SearchBase`, `-ComputerName`.

Un check fallito non interrompe l'assessment: viene registrato in
`AssessmentResult.Metadata.CheckResults` con `Status`/`ErrorType`/`ErrorMessage`.

#### `New-AssessmentADAssessmentResult`
Costruisce/inizializza un oggetto `TechHubADAssessmentResult` vuoto (usato
internamente dall'engine; raramente necessario chiamarlo a mano).

---

### 5.5 Export

Tutti prendono in input il risultato di `Invoke-AssessmentADAssessment`.

```powershell
$Assessment = Invoke-AssessmentADAssessment

Export-AssessmentADAssessmentJson -Assessment $Assessment -Path .\report.json
Export-AssessmentADAssessmentCsv  -Assessment $Assessment -Path .\report.csv
Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path .\report.html
```

- `Export-AssessmentADAssessmentJson` — parametri: `-Assessment` (mandatory),
  `-Path` (opzionale, altrimenti stampa a schermo), `-Depth`.
- `Export-AssessmentADAssessmentCsv` — parametri: `-Assessment`, `-Path` (entrambi mandatory).
- `Export-AssessmentADAssessmentHtml` — parametri: `-Assessment`, `-Path` (entrambi mandatory).

---

## 6. Guida: come lanciare i vari assessment

Questa sezione risponde a "come lancio l'assessment che mi serve", dal più
completo (un comando) al più granulare (una singola funzione). Scegli il
livello in base a quanto controllo ti serve: più scendi, più devi comporre
tu i pezzi, ma più puoi restringere cosa viene eseguito.

```
Livello 1  Invoke-AssessmentADFullAssessment      → tutto, un comando, un report
Livello 2  Invoke-AssessmentADAssessment           → solo i check di sicurezza AD
Livello 3  Invoke-AssessmentADRemoteAssessment /
           Invoke-AssessmentADRemoteLocalGroups    → solo l'infrastruttura remota
Livello 4  Get-AssessmentAD<Check> /
           Get-AssessmentADRemote<Collector>       → una singola funzione
```

In ogni sezione: import del modulo omesso per brevità (fallo una volta
all'inizio della sessione con `Import-Module .\TechHub.ActiveDirectory.psd1 -Force`).

---

### 6.1 Livello 1 — Assessment completo (consigliato per iniziare)

Un comando solo: esegue tutti gli 11 check di sicurezza AD, raccoglie i dati
infrastrutturali dai computer remoti e scrive un unico report HTML.

```powershell
$Result = Invoke-AssessmentADFullAssessment -Server dc01.example.test

$Result.ReportPath          # percorso del report HTML scritto
$Result.Assessment.Summary  # riepilogo rapido a schermo
```

Varianti:

```powershell
# Computer specifici invece della discovery automatica, e path del report a scelta
Invoke-AssessmentADFullAssessment -Server dc01.example.test -ComputerName 'srv01','srv02' -OutputPath .\report.html

# Solo i client, non i server
Invoke-AssessmentADFullAssessment -Server dc01.example.test -TargetType Client

# Solo i check di sicurezza AD, senza contattare nessuna macchina remota
Invoke-AssessmentADFullAssessment -Server dc01.example.test -SkipRemoteAssessment
```

Usa questo livello quando: è la prima volta, vuoi un report da consegnare,
non ti serve scegliere singolarmente cosa girare.

---

### 6.2 Livello 2 — Solo l'assessment di sicurezza Active Directory

Usa `Invoke-AssessmentADAssessment` quando ti interessano solo i check AD
(delegazione, Kerberos, password policy, ACL, gruppi privilegiati), senza
toccare macchine remote. Utile per un giro veloce o per integrare l'output
in un tuo script.

**Tutti i check:**
```powershell
$Assessment = Invoke-AssessmentADAssessment -Server dc01.example.test

$Assessment.Summary
$Assessment.Findings | Format-Table CheckId, Severity, Title -AutoSize
```

**Una sola categoria** (`Delegation`, `Kerberos`, `Authentication`,
`PrivilegedAccess`, `AccountHygiene`, `Hardening`, `AuditingAndLogging`,
`DNS`, `DisasterRecovery`):
```powershell
Invoke-AssessmentADAssessment -Server dc01.example.test -Category 'Hardening'
```

> Nota: alcuni check in `Hardening`, `AuditingAndLogging` e `AD-DNS-ZONE-SECURITY`
> agiscono su computer remoti o richiedono il modulo `DnsServer` — se li lanci
> tramite `Invoke-AssessmentADAssessment` senza indicare un target valido,
> alcuni potrebbero non produrre risultati o segnalare `NotAvailable`. Per
> questi conviene spesso chiamarli direttamente (Livello 4) con `-ComputerName`
> esplicito.

**Un solo check**, per CheckId — utile per validare una correzione o fare un
controllo mirato:
```powershell
Invoke-AssessmentADAssessment -Server dc01.example.test -CheckId 'AD-DCSYNC-RIGHTS'
```

CheckId disponibili: `AD-UNCONSTRAINED-DELEGATION`, `AD-CONSTRAINED-DELEGATION`,
`AD-RBCD`, `AD-KERBEROASTING`, `AD-ASREP-ROASTING`, `AD-KRBTGT-PASSWORD-AGE`,
`AD-PASSWORD-POLICY`, `AD-DCSYNC-RIGHTS`, `AD-SHADOW-ADMIN`,
`AD-PRIVILEGED-GROUP`, `AD-REMOTE-LOCAL-GROUPS` (l'elenco esatto:
`(New-AssessmentADCheckRegistry).GetAll() | Format-Table CheckId, Category`).

**Esportazione manuale** (quando non usi il wrapper di Livello 1):
```powershell
Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path .\report.html
Export-AssessmentADAssessmentJson -Assessment $Assessment -Path .\report.json
Export-AssessmentADAssessmentCsv  -Assessment $Assessment -Path .\report.csv
```

Usa questo livello quando: ti interessa solo la parte AD, vuoi filtrare per
categoria/check, o vuoi gestire tu l'export.

---

### 6.3 Livello 3 — Solo l'assessment infrastrutturale remoto

Usa questo livello quando vuoi i dati raccolti dai computer Windows senza
rieseguire i check AD.

**Tutti i collector su una lista di computer, uniti in un solo assessment**
(la prima chiamata con `-Assessment $null` ne crea uno nuovo; le successive
lo riusano e accumulano i dati):
```powershell
$Assessment = $null

foreach ($Computer in 'srv01', 'srv02') {
    $Assessment = Invoke-AssessmentADRemoteAssessment -ComputerName $Computer -Assessment $Assessment
}

Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path .\report-remoto.html
```

**Tutti i collector su computer scoperti automaticamente in AD:**
```powershell
$Provider = New-AssessmentADProvider -Server dc01.example.test
$Targets = Get-AssessmentADRemoteTargets -Provider $Provider -TargetType Server
$Assessment = $null

foreach ($Target in $Targets) {
    $Assessment = Invoke-AssessmentADRemoteAssessment -ComputerName $Target.ComputerName -Assessment $Assessment
}
```

**Solo alcuni collector** (valori validi: `ServiceAccounts`, `ScheduledTasks`,
`IISAppPools`, `LocalGroups`, `NetworkShares`, `OSInfo`, `WindowsFeatures`):
```powershell
Invoke-AssessmentADRemoteAssessment -ComputerName 'srv01' -Collector 'OSInfo', 'WindowsFeatures'
```

**Solo i gruppi locali, su più computer scoperti da AD** (scorciatoia dedicata,
non passa dagli altri collector):
```powershell
Invoke-AssessmentADRemoteLocalGroups -Provider $Provider -TargetType Server |
    Where-Object { $_.GroupName -eq 'Administrators' }
```

Usa questo livello quando: i check AD sono già stati fatti (o non ti servono
ora), e vuoi solo il quadro infrastrutturale, magari su un sottoinsieme di
macchine.

---

### 6.4 Livello 4 — Una singola funzione (debug, verifica mirata)

Ogni check e ogni collector è comunque richiamabile da solo. È il livello
più usato durante il debug in laboratorio, per isolare un problema.

**Un singolo check di sicurezza AD:**
```powershell
Get-AssessmentADKerberoasting -Server dc01.example.test -Verbose
```

**Un singolo collector remoto:**
```powershell
Get-AssessmentADRemoteOSInfo -ComputerName 'srv01' -Verbose
```
`-Verbose` mostra quale trasporto è stato usato (WinRM/WSMan o WMI/DCOM) e
dove eventualmente fallisce — il primo strumento di diagnosi quando un
collector non ritorna niente.

Usa questo livello quando: un check/collector specifico si comporta in modo
strano e vuoi isolarlo, oppure ti serve solo quel dato puntuale.

---

## 7. Testing

Il modulo usa Pester (v6). Dalla cartella del modulo:
```powershell
Invoke-Pester -Path .\Tests -PassThru
```
I test usano mock/oggetti sintetici: non serve un dominio AD reale né
macchine Windows reali per farli passare. Sono complementari, non
sostitutivi, ai test in laboratorio su infrastruttura vera.

## 8. Limitazioni note

- `Get-AssessmentADRemoteOSInfo` dichiara `WindowsInstallationType` nel
  proprio output ma non lo valorizza mai (sempre `$null`).
- Nessuna pipeline CI nel repository: i test vanno eseguiti manualmente.
- `Get-AssessmentADPrivilegedGroup` — vedi nota nella sezione 5.1.
- `Get-AssessmentADRemoteAuditPolicy` fa il parsing dell'output CSV di `auditpol /get /r`, il cui formato può variare in base a lingua/versione del sistema operativo remoto. Validare in laboratorio prima di usarlo su larga scala.
- `Get-AssessmentADDNSZoneSecurity` richiede il modulo `DnsServer` (non incluso in `ActiveDirectory`), tipicamente presente solo su un DC che ospita anche il ruolo DNS.
- L'area Group Policy (delega GPO, GPP password cache, igiene OU/link) è **esclusa per scelta** dal registro dei check.
