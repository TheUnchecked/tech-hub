# Assessment.ActiveDirectory

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
Import-Module .\Assessment.ActiveDirectory.psd1
```

---

## Usage

### 1. Run the assessment and keep the result in a variable

`Invoke-AssessmentADAssessment` returns a single `AssessmentADAssessmentResult`
object. It is only held in memory for the lifetime of the current PowerShell
session/process, so it must be captured in a variable before it can be
exported. If the session is closed (or the variable is overwritten) without
exporting first, the result is lost and the assessment must be run again.

```powershell
$assessment = Invoke-AssessmentADAssessment -Verbose
```

Optional filters:

```powershell
# Only one category
$assessment = Invoke-AssessmentADAssessment -Category Delegation

# Only specific checks
$assessment = Invoke-AssessmentADAssessment -CheckId AD-UNCONSTRAINED-DELEGATION,AD-RBCD
```

### 2. Export the same variable to CSV, HTML and/or JSON

Each format has its own `Export-AssessmentAD*` function. `-Path` must point
to a file (the parent folder is created automatically if missing). Run any
combination of the three — they all read from the same `$assessment`
variable and do not affect each other:

```powershell
$assessment | Export-AssessmentADAssessmentJson -Path C:\Report\ad-assessment.json
$assessment | Export-AssessmentADAssessmentCsv  -Path C:\Report\ad-assessment.csv
$assessment | Export-AssessmentADAssessmentHtml -Path C:\Report\ad-assessment.html
```

If you see an error such as *"Cannot bind argument to parameter 'Assessment'
because it is null"* or *"The supplied object is not a valid
AssessmentADAssessmentResult"*, it means `$assessment` is empty, was never
set, or belongs to a different (closed) session — re-run step 1 first.

### 3. Remote infrastructure collectors (optional, separate from `$assessment`)

`AD-REMOTE-LOCAL-GROUPS` is registry-driven and already runs as part of
`Invoke-AssessmentADAssessment`, so its findings are included in
`$assessment` automatically. The other remote collectors below are **not**
registry-driven: they return their own objects and are **not** merged into
`$assessment` automatically. Capture and export them separately if needed:

```powershell
$remote = 'SRV-WEB01','SRV-FILE01' |
    Invoke-AssessmentADRemoteAssessment -Collector OSInfo,NetworkShares

$remote | Export-AssessmentADAssessmentJson -Path C:\Report\remote-infra.json
```

They require WinRM/WS-Man (preferred) or DCOM/CIM connectivity to the
targets; a failure to reach a target surfaces as a `Status = 'NotAvailable'`
record with `ErrorType`/`ErrorMessage` populated, rather than throwing.