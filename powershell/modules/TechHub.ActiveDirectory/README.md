# TechHub.ActiveDirectory

Read-only Active Directory security assessment functions for Windows PowerShell 5.1.

## Scope

The module detects accounts configured with unconstrained Kerberos delegation through the `TRUSTED_FOR_DELEGATION` userAccountControl flag (`0x80000`), constrained delegation through `msDS-AllowedToDelegateTo`, and resource-based constrained delegation (RBCD) through `msDS-AllowedToActOnBehalfOfOtherIdentity`. It distinguishes account types, reports enabled or disabled state, and includes available service principal names.

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

```powershell
Get-TechHubADConstrainedDelegation -Verbose
```

```powershell
Get-TechHubADRBCD -Verbose
```

```powershell
Get-TechHubADPrivilegedGroup -Verbose -IncludeDisabled
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
- Constrained delegation findings additionally include `AllowedToDelegateTo`, `CriticalMatches`, `DocumentedMatches`, and `ExcludedMatches` in `Evidence`.
- RBCD findings include `TargetObject`, `TargetObjectType`, `AllowedIdentities`, `ResolvedIdentities`, `UnresolvedSids`, `AccountEnabled`, and `SecurityDescriptorPresent` in `Evidence`.
- `Risk`, `Recommendation`, and `References`.
- `CollectedAt`, `Domain`, `Forest`, and `DomainController` when available.
- `IsReadOnly`, which is always `$true`.

### Severity

- `High`: enabled account configured for unconstrained delegation.
- `Medium`: disabled account configured for unconstrained delegation.

For constrained delegation, severity is deterministic and configurable:

- `High`: a destination matches one of the caller-supplied `-CriticalServicePatterns`.
- `Medium`: more than one destination exists, or a supplied documentation baseline does not cover every destination.
- `Low`: one destination exists without a supplied critical or baseline match.
- `Informational`: the account is disabled, or every destination matches `-ExcludedServicePatterns` (`Status = NotApplicable`).

The module does not embed an arbitrary critical-service list. `-CriticalServicePatterns`, `-DocumentedServicePatterns`, and `-ExcludedServicePatterns` accept PowerShell wildcard patterns and must be supplied by the assessing organization.

```powershell
Get-TechHubADConstrainedDelegation `
    -CriticalServicePatterns 'LDAP/*', 'CIFS/dc*' `
    -DocumentedServicePatterns 'HTTP/*.example.test'
```

RBCD severity is also configurable. `-SensitiveTargetPatterns`, `-ApprovedIdentityPatterns`, and `-ExcludedIdentityPatterns` accept wildcard patterns. Without these baselines, an RBCD configuration is reported as a review item and is not automatically classified as critical.

```powershell
Get-TechHubADRBCD `
    -SensitiveTargetPatterns 'CN=DC*' `
    -ApprovedIdentityPatterns 'S-1-5-21-100-200-300-*' `
    -ExcludedIdentityPatterns 'S-1-5-21-100-200-300-9999'
```

Privileged group assessment uses these default group names when present: `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators`, `Server Operators`, `Backup Operators`, and `Domain Controllers`. `-GroupPatterns` extends the analyzed group set; `-PrivilegedGroupPatterns` identifies additional high-privilege groups.

`Get-TechHubADPrivilegedGroup` reports direct and indirect membership, nesting paths, normalized user/computer/group objects, disabled accounts, `adminCount`, and `PasswordNeverExpires`. Missing default groups are ignored. Disabled members are excluded by default and can be included with `-IncludeDisabled`.

Severity is deterministic and review-oriented. Approved or excluded members are `Informational`; disabled members, non-documented membership, password-never-expires, and nested groups produce `Medium` where applicable; service-account indicators, `adminCount`, or unapproved membership in a configured privileged group can produce `High`; a nested unapproved identity in a high-privilege group can produce `Critical`. Service accounts are identified only with the optional `-ServiceAccountPatterns` parameter.

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
