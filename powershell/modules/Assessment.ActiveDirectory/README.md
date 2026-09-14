# Assessment.ActiveDirectory

Read-only Active Directory security assessment and remote infrastructure inventory functions for Windows PowerShell 5.1.

## Scope

Every function is independent and self-contained: it takes computer/domain
parameters, queries directly (Active Directory cmdlets or CIM/WinRM), and
returns plain objects. There is no shared engine, registry, or provider
abstraction — you call the functions you need and combine the results
yourself.

**Active Directory security checks** (direct `Get-AD*` queries):

- `Get-AssessmentADUnconstrainedDelegation` — accounts with the `TRUSTED_FOR_DELEGATION` flag (`0x80000`).
- `Get-AssessmentADConstrainedDelegation` — accounts with `msDS-AllowedToDelegateTo`.
- `Get-AssessmentADRBCD` — objects with `msDS-AllowedToActOnBehalfOfOtherIdentity`, parsed into the list of identities allowed to delegate.
- `Get-AssessmentADPrivilegedGroup` — recursive membership of privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, Domain Controllers, plus any extra patterns supplied).
- `Get-AssessmentADInventory` — users, computers, groups, MSA/gMSA, OUs.

These functions report **facts only** — they do not compute a risk severity.
That judgment is left to whoever reads the output.

**Remote infrastructure collectors** (CIM — WSMan falling back to DCOM —
or WinRM/`Invoke-Command` depending on the collector):

- `Get-AssessmentADRemoteTargets` — discovers/classifies computers from AD.
- `Get-AssessmentADRemoteOSInfo` — OS caption, version, build, SKU, installation type.
- `Get-AssessmentADRemoteWindowsFeatures` — installed roles/features.
- `Get-AssessmentADRemoteServiceAccounts` — Windows service logon accounts.
- `Get-AssessmentADRemoteScheduledTaskAccounts` — scheduled task run-as accounts.
- `Get-AssessmentADRemoteIISAppPoolAccounts` — IIS application pool identities.
- `Get-AssessmentADRemoteNetworkShareACLs` — SMB shares and share-level ACLs.
- `Get-AssessmentADRemoteUserRightAssignments` — local user rights (via `secedit`), with GPO display names.
- `Get-AssessmentADRemoteLocalGroupMembers` — one record per local group, with raw member data.
- `Get-AssessmentADRemoteLocalGroups` — the same data flattened to one record per member, classified as LocalAccount/DomainPrincipal/BuiltInPrincipal/WellKnownPrincipal/Unknown.

The module does not perform exploitation, credential dumping, lateral
movement, persistence, ticket forging, bypass, evasion, or configuration
changes, and it does not contain, request, or store credentials (beyond an
optional `-Credential` you supply yourself).

Before every WSMan/WinRM (port 5985) or DCOM/RPC (port 135) connection
attempt, the remote collectors run a bounded TCP reachability check (10
seconds). A powered-off or unreachable host fails fast with a clear error
instead of letting `New-CimSession`/`Invoke-Command` hang for minutes, which
matters when assessing a large number of computers.

---

## Requirements

- Windows PowerShell 5.1.
- RSAT Active Directory module for the AD security checks and `Get-AssessmentADInventory`.
- Read access to the queried Active Directory objects.
- Appropriate remote permissions for remote infrastructure collectors.
- Network connectivity to the queried systems: WinRM/WS-Man, CIM/DCOM, or RPC depending on the collector (each function's help topic states which).

---

## Import

```powershell
Import-Module .\Assessment.ActiveDirectory.psd1
```

---

## Usage

### Run individual checks

Every function returns plain objects directly — nothing to capture in a
special container first:

```powershell
Get-AssessmentADUnconstrainedDelegation -Verbose
Get-AssessmentADPrivilegedGroup -GroupPatterns 'CONTOSO\Tier0-*'
Get-AssessmentADRemoteOSInfo -ComputerName SRV01,SRV02
```

### Run all four AD security checks at once

`Invoke-AssessmentADAssessment` calls the four checks in sequence and
returns one combined array, each record tagged with the `CheckId` that
produced it:

```powershell
$assessment = Invoke-AssessmentADAssessment -Verbose

# Only some checks
$assessment = Invoke-AssessmentADAssessment -CheckId AD-UNCONSTRAINED-DELEGATION, AD-RBCD
```

### Run remote collectors against a set of computers

`Invoke-AssessmentADRemoteAssessment` dispatches to the selected
`Get-AssessmentADRemote*` collectors and tags each record with the
`Collector` name:

```powershell
$remote = 'SRV-WEB01','SRV-FILE01' |
    Invoke-AssessmentADRemoteAssessment -Collector OSInfo, NetworkShares

# All collectors, explicit target discovery from AD first
$computers = Get-AssessmentADRemoteTargets -TargetType Server | Select-Object -ExpandProperty ComputerName
$remote = $computers | Invoke-AssessmentADRemoteAssessment
```

A collector that fails outright for a computer produces one record with
`Status = 'Error'` and the failure message, instead of throwing and losing
that computer's data.

### Export to JSON, CSV or HTML

The three `Export-AssessmentAD*` functions accept **any array of objects**
— the output of a single function, of `Invoke-AssessmentADAssessment`, of
`Invoke-AssessmentADRemoteAssessment`, or a manual combination of several
calls. `-Path` must point to a file (the parent folder is created
automatically if missing):

```powershell
$assessment | Export-AssessmentADAssessmentJson -Path C:\Report\ad-assessment.json
$assessment | Export-AssessmentADAssessmentCsv  -Path C:\Report\ad-assessment.csv
$assessment | Export-AssessmentADAssessmentHtml -Path C:\Report\ad-assessment.html -Title 'contoso.com'

# Combine AD checks and remote infrastructure into one report
@($assessment) + @($remote) | Export-AssessmentADAssessmentHtml -Path C:\Report\full.html
```

CSV and HTML group/flatten records generically (by `CheckId`/`Collector`
when present) — they make no assumption about which fields a given check or
collector returns, so the same export functions work for every current and
future function in this module.
