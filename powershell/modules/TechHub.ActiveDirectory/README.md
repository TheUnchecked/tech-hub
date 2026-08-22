# TechHub.ActiveDirectory

Read-only Active Directory security assessment functions for Windows PowerShell 5.1.

## Scope

The first vertical slice detects accounts configured with unconstrained Kerberos delegation through the `TRUSTED_FOR_DELEGATION` userAccountControl flag (`0x80000`). It distinguishes computer and user accounts, reports enabled or disabled state, and includes available service principal names.

This module is an assessment tool only. It does not perform exploitation, credential dumping, lateral movement, persistence, ticket forging, bypass, evasion, or configuration changes.

## Requirements

- Windows PowerShell 5.1.
- RSAT Active Directory module.
- Read access to the queried Active Directory objects.
- Network connectivity to a domain controller.

The module does not contain credentials and does not request or store credentials.

## Import

```powershell
Import-Module .\TechHub.ActiveDirectory.psd1
```

## Usage

```powershell
Get-TechHubADUnconstrainedDelegation -Verbose
```

Optional read-only query scoping:

```powershell
Get-TechHubADUnconstrainedDelegation `
    -Server 'dc01.example.test' `
    -SearchBase 'OU=Servers,DC=example,DC=test' `
    -ErrorAction Stop
```

Use placeholder values only in documentation and examples. Do not place production identifiers, credentials, or secrets in the repository.

## Output

The command writes only structured PowerShell objects to the success pipeline. Each finding contains:

- `AssessmentId`, `CheckId`, `CheckName`, and `FindingId`.
- `Title`, `Description`, `Category`, `Severity`, `Confidence`, and `Status`.
- `AffectedObject` with name, object class, and enabled state.
- `ObjectType`, `DistinguishedName`, `SamAccountName`, and `ObjectGuid`.
- `Evidence` with the userAccountControl value, delegation flag, account state, and SPNs.
- `Risk`, `Recommendation`, and `References`.
- `CollectedAt`, `Domain`, `Forest`, and `DomainController` when available.
- `IsReadOnly`, which is always `$true`.

### Severity

- `High`: enabled account configured for unconstrained delegation.
- `Medium`: disabled account configured for unconstrained delegation.

### Confidence

- `High`: required delegation and identity data was available.
- `Medium`: the delegation flag was available but contextual properties were incomplete.

## Error handling

Empty results are a valid assessment outcome and produce no success-pipeline objects. LDAP and discovery errors are written to the error stream and can be controlled with `-ErrorAction`. Diagnostic information is available through `-Verbose`.

## Testing

The unit tests use synthetic objects and Pester mocks only. They do not connect to a domain, domain controller, tenant, or production environment.

```powershell
Invoke-Pester .\Tests\Get-TechHubADUnconstrainedDelegation.Tests.ps1
```

## Security and read-only guarantees

The module performs only read operations through the Active Directory PowerShell cmdlets. It does not modify AD objects, groups, ACLs, GPOs, registry settings, or server configuration. Remediation recommendations are informational and must be executed through a separately reviewed administrative process.
