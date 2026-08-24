# TechHub.ActiveDirectory

Read-only Active Directory security assessment and remote infrastructure assessment functions for Windows PowerShell 5.1.

## Scope

The module provides two complementary assessment capabilities:

1. **Active Directory Security Assessment**
2. **Generic Remote Infrastructure Assessment**

The two capabilities are intentionally separated.

The Active Directory security assessment detects:

- Unconstrained Kerberos delegation through the `TRUSTED_FOR_DELEGATION` userAccountControl flag (`0x80000`).
- Constrained delegation through `msDS-AllowedToDelegateTo`.
- Resource-based constrained delegation (RBCD) through `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Privileged Active Directory group membership and associated risk indicators.

The remote infrastructure assessment collects read-only configuration and security-relevant information from Windows computers:

- Service logon accounts.
- Scheduled task run-as accounts.
- IIS application pool accounts.
- Local group membership.
- Network share ACLs.
- Operating system information.
- Installed Windows features.

The remote collectors are generic assessment components. They are not tied exclusively to the Tier Model and can be used as part of a general infrastructure assessment.

The module does not perform exploitation, credential dumping, lateral movement, persistence, ticket forging, bypass, evasion, or configuration changes.

---

## Requirements

- Windows PowerShell 5.1.
- RSAT Active Directory module for Active Directory checks.
- Read access to the queried Active Directory objects.
- Appropriate remote permissions for remote infrastructure collectors.
- Network connectivity to the queried systems.
- WinRM/WS-Man, CIM, DCOM/RPC, or other required Windows management protocols depending on the collector.

The module does not contain credentials and does not request or store credentials.

---

## Import

```powershell
Import-Module .\TechHub.ActiveDirectory.psd1