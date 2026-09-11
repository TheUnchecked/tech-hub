# TechHub.ActiveDirectory Providers

## Purpose

The provider layer collects Active Directory data, normalizes it into predictable PowerShell objects, and returns structured operation results. It does not calculate severity, create findings, orchestrate checks, or generate reports.

## Active Directory provider

`TechHubADProvider` is created with:

```powershell
$Provider = New-AssessmentADProvider -Server 'dc01.example.test'
```

Supported read-only operations:

- `GetDomainInformation()`
- `GetForestInformation()`
- `GetDomainControllers()`
- `GetADObjects($LdapFilter, $SearchBase, $Properties)`
- `GetGroups($SearchBase, $Filter)`
- `GetGroupMembers($GroupIdentity)`
- `GetDefaultDomainPasswordPolicy()`
- `GetFineGrainedPasswordPolicies()`
- `GetObjectSecurityDescriptor($Identity)`

The provider never accepts scriptblocks or arbitrary commands. When `-Server` is omitted, the Active Directory module performs its normal automatic discovery.

## Result shape

Every operation returns an object containing:

- `Provider`
- `Operation`
- `Status`
- `Data`
- `ErrorType`
- `ErrorMessage`
- `Server`
- `IsReadOnly`

`Data` contains normalized objects with nullable properties such as `Name`, `SamAccountName`, `DistinguishedName`, `ObjectGUID`, `ObjectClass`, `ObjectCategory`, `Enabled`, `UserAccountControl`, `AdminCount`, `PasswordNeverExpires`, `ServicePrincipalName`, `MemberOf`, `msDS-AllowedToDelegateTo`, and `SID`.

`msDS-AllowedToDelegateTo` is an optional read-only normalized property for constrained delegation targets. It is `$null` when the source attribute is absent, null, or empty, and is a `[string[]]` when one or more values are present. Values retain the order returned by Active Directory and are not modified by the provider. The provider exposes the property only when it is explicitly requested through `GetADObjects()`.

Domain and forest operations preserve their specific metadata such as `DNSRoot`, `NetBIOSName`, `DomainMode`, `ForestMode`, `RootDomain`, and `Domains`.

`GetDefaultDomainPasswordPolicy()` and `GetFineGrainedPasswordPolicies()` return the raw policy objects from Active Directory (`MinPasswordLength`, `ComplexityEnabled`, `ReversibleEncryptionEnabled`, `LockoutThreshold`, and related properties); they are not passed through the `GetADObjects()` normalizer.

`GetObjectSecurityDescriptor($Identity)` returns one normalized access-control entry (ACE) per `Data` item: `IdentityReference`, `ActiveDirectoryRights` (string), `ObjectTypeGuid` (the extended right or property-set GUID the ACE applies to, or an all-zero GUID when it applies to the whole object), `AccessControlType` (`Allow`/`Deny`), and `IsInherited`. It reads the object's `nTSecurityDescriptor` attribute; it never modifies an ACL.

## Status semantics

The provider uses the existing status values:

- `Available`: the operation completed successfully.
- `Partial`: the aggregate provider state contains both successful and unavailable/error operations.
- `NotAvailable`: the ActiveDirectory module is unavailable for an operation, or no operation has completed for aggregate status.
- `Error`: an operation failed, or all completed operations failed.

The provider preserves successful operation results when another operation fails. The caller can inspect each operation result and continue independently.

`ErrorType` distinguishes `ModuleUnavailable`, `AccessDenied`, `LdapError`, `ObjectNotFound`, `ServerUnavailable`, and `ProviderError` where the underlying error can be classified.

## Read-only behavior

Only Active Directory read cmdlets are used: `Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`, `Get-ADObject`, `Get-ADGroup`, `Get-ADGroupMember`, `Get-ADDefaultDomainPasswordPolicy`, and `Get-ADFineGrainedPasswordPolicy`. `GetObjectSecurityDescriptor()` reads an ACL by requesting the `nTSecurityDescriptor` property through `Get-ADObject`; it does not call `Set-Acl`/`Set-ADObject` or otherwise modify a security descriptor. The provider does not modify AD, ACLs, GPOs, registry, or filesystem state. It does not contain credentials, execute dynamic code, calculate risk, or create findings.

## Testing and limitations

Unit tests use Pester mocks and synthetic objects only. No real domain, domain controller, ADWS, WinRM, or production environment is required.

The provider does not perform retries, pagination policy, caching, health assessment, authorization decisions, or severity classification. Those responsibilities belong to future layers. Availability of optional AD attributes depends on the permissions and capabilities of the connected environment.
