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
Check attualmente registrati: `AD-UNCONSTRAINED-DELEGATION`,
`AD-CONSTRAINED-DELEGATION`, `AD-RBCD`, `AD-PRIVILEGED-GROUP`,
`AD-REMOTE-LOCAL-GROUPS`.

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

## 6. Scenari d'uso tipici

### Assessment AD completo con export
```powershell
Import-Module .\TechHub.ActiveDirectory.psd1 -Force

$Assessment = Invoke-AssessmentADAssessment -Server dc01.example.test

$Assessment.Summary
$Assessment.Findings | Format-Table CheckId, Severity, Title -AutoSize

Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path .\report.html
```

### Solo assessment infrastrutturale remoto su un gruppo di server
```powershell
$Provider = New-AssessmentADProvider -Server dc01.example.test

Invoke-AssessmentADRemoteLocalGroups -Provider $Provider -TargetType Server |
    Where-Object { $_.GroupName -eq 'Administrators' }
```

### Singolo collector, per debug/verifica in lab
```powershell
Get-AssessmentADRemoteOSInfo -ComputerName 'srv01' -Verbose
```
`-Verbose` è utile in laboratorio per vedere quale transport è stato usato
(WinRM/WSMan o WMI/DCOM) e dove eventualmente fallisce.

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
