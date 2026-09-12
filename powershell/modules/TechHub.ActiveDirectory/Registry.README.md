# Active Directory Check Registry

## Purpose

The check registry is declarative metadata for the Active Directory assessment framework. It describes available checks for a future Assessment Engine without executing checks or querying Active Directory.

## CheckDefinition

Each definition contains:

- `CheckId`
- `Name`
- `Description`
- `Category`
- `Version`
- `Enabled`
- `IsReadOnly`
- `FunctionName`
- `RequiredProviders`
- `RequiredModules`
- `Tags`

The registry validates required metadata and rejects writable definitions. It does not inspect or invoke the function named by `FunctionName`.

## Lifecycle

```powershell
$Registry = New-AssessmentADCheckRegistry
$Registry.Get('AD-RBCD')
$Registry.FindByCategory('Delegation')
$Registry.FindByProvider('TechHubADProvider')
$Registry.SetEnabled('AD-RBCD', $false)
```

`Register()` adds a definition and rejects duplicate `CheckId` values. `Get()`, `GetAll()`, `FindByCategory()`, and `FindByProvider()` return metadata only. `SetEnabled()` changes metadata only; it does not prevent direct invocation of a function and does not execute anything.

## Registered checks

The default registry contains:

- `AD-UNCONSTRAINED-DELEGATION` -> `Get-AssessmentADUnconstrainedDelegation` (Delegation)
- `AD-CONSTRAINED-DELEGATION` -> `Get-AssessmentADConstrainedDelegation` (Delegation)
- `AD-RBCD` -> `Get-AssessmentADRBCD` (Delegation)
- `AD-KERBEROASTING` -> `Get-AssessmentADKerberoasting` (Kerberos)
- `AD-ASREP-ROASTING` -> `Get-AssessmentADASREPRoasting` (Kerberos)
- `AD-KRBTGT-PASSWORD-AGE` -> `Get-AssessmentADKrbtgtPasswordAge` (Kerberos)
- `AD-PASSWORD-POLICY` -> `Get-AssessmentADPasswordPolicy` (Authentication)
- `AD-DCSYNC-RIGHTS` -> `Get-AssessmentADDCSyncRights` (PrivilegedAccess)
- `AD-SHADOW-ADMIN` -> `Get-AssessmentADShadowAdminRights` (PrivilegedAccess)
- `AD-PRIVILEGED-GROUP` -> `Get-AssessmentADPrivilegedGroup` (PrivilegedAccess)
- `AD-REMOTE-LOCAL-GROUPS` -> `Get-AssessmentADRemoteLocalGroups` (PrivilegedAccess)
- `AD-STALE-ACCOUNTS` -> `Get-AssessmentADStaleAccounts` (AccountHygiene)
- `AD-PASSWORD-NEVER-EXPIRES` -> `Get-AssessmentADPasswordNeverExpiresAccounts` (AccountHygiene)
- `AD-PROTECTED-USERS-COVERAGE` -> `Get-AssessmentADProtectedUsersCoverage` (Hardening)
- `AD-AUTH-HARDENING` -> `Get-AssessmentADRemoteAuthenticationHardening` (Hardening)
- `AD-CREDENTIAL-GUARD` -> `Get-AssessmentADRemoteCredentialGuardStatus` (Hardening)
- `AD-OBSOLETE-OS` -> `Get-AssessmentADRemoteObsoleteOperatingSystem` (Hardening)
- `AD-AUDIT-POLICY` -> `Get-AssessmentADRemoteAuditPolicy` (AuditingAndLogging)
- `AD-DNS-ZONE-SECURITY` -> `Get-AssessmentADDNSZoneSecurity` (DNS)
- `AD-RECYCLE-BIN` -> `Get-AssessmentADRecycleBinStatus` (DisasterRecovery)

TrustedToAuth is not registered because it is not currently implemented. Group Policy-based checks (GPO delegation, GPP cached passwords, OU/link hygiene) are intentionally out of scope for this registry.

Every definition except `AD-REMOTE-LOCAL-GROUPS` requires `TechHubADProvider` and the `ActiveDirectory` module. `AD-REMOTE-LOCAL-GROUPS` requires no provider; it drives the generic remote local-group collector instead. `AD-DNS-ZONE-SECURITY` additionally requires the `DnsServer` module - a dependency distinct from every other check, which use only `ActiveDirectory`. All definitions declare `IsReadOnly = $true`.

## Categories and future engine

Current categories are `Delegation`, `Kerberos`, `Authentication`, `PrivilegedAccess`, `AccountHygiene`, `Hardening`, `AuditingAndLogging`, `DNS`, and `DisasterRecovery`. A future Assessment Engine may use registry metadata to select enabled checks and verify provider/module prerequisites. That engine is intentionally outside this slice.

The registry does not calculate severity, create findings, query AD, load customer configuration, generate reports, or contain credentials.
