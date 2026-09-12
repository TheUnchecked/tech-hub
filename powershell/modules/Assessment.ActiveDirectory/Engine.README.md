# Active Directory Assessment Engine

## Purpose

`Invoke-AssessmentADAssessment` is the first orchestration layer for the registered Active Directory checks. It discovers check definitions from `New-AssessmentADCheckRegistry`, resolves their function names safely, executes enabled read-only checks, and returns a `AssessmentADAssessmentResult`.

It does not contain a hardcoded check list, query Active Directory itself, create providers, calculate severity, or generate reports.

## Lifecycle

```text
Registry -> select enabled definitions -> resolve function -> execute check -> add findings -> complete AssessmentResult
```

For each selected definition the engine:

1. reads `CheckId`, `Name`, `Category`, `Enabled`, `FunctionName`, `RequiredProviders`, and `IsReadOnly`;
2. applies optional `-CheckId` and `-Category` filters;
3. skips disabled checks;
4. refuses definitions that do not declare `IsReadOnly = $true`;
5. resolves only PowerShell functions with `Get-Command`;
6. executes the resolved command and adds objects containing `FindingId` to `Findings`;
7. records failures in `AssessmentResult.Metadata.CheckResults`;
8. completes the assessment with timestamps, duration, summary, and data availability.

Before execution, if at least one selected definition requires `AssessmentAD` or `AssessmentADProvider`, the engine creates one `AssessmentADProvider` with `-Server` unless the caller supplied `-Provider`. That same instance is reused for every provider-aware check in the assessment. Legacy checks that do not expose `-Provider` keep their existing invocation behavior.

## Usage

```powershell
Invoke-AssessmentADAssessment
Invoke-AssessmentADAssessment -CheckId 'AD-RBCD'
Invoke-AssessmentADAssessment -Category 'Delegation'
```

`-Server`, `-SearchBase`, and `-Provider` are passed only when the resolved check function exposes a parameter with that name. Existing checks remain compatible because they are not forced to accept a provider.

`RequiredProviders` is recognized as registry metadata. This transitional engine does not refactor or gate legacy checks on provider injection; future engine versions may add explicit provider prerequisite handling.

## Failures and statuses

A failed check does not terminate the assessment. Structured entries contain `CheckId`, `CheckName`, `Status`, `ErrorType`, `ErrorMessage`, `StartedAt`, `CompletedAt`, `Duration`, and `IsReadOnly`.

The engine uses existing status values:

- `Available`: a provider context was supplied.
- `NotAvailable`: no provider context was supplied, or a check was disabled.
- `Partial`: at least one check failed while other checks were processed.
- `Error`: a check execution or read-only validation failed; the assessment itself continues.

Assessment `DataAvailability` is `Complete` when selected checks do not fail and `Partial` otherwise.

## Read-only boundary

The engine executes only functions declared read-only by the registry. It does not invoke arbitrary command strings, use `Invoke-Expression`, query AD directly, modify AD, or generate reports. Check logic remains responsible for its own read-only implementation.

## Testing

Engine tests use synthetic registry definitions and synthetic PowerShell functions. They do not connect to Active Directory or mock real AD operations. They validate discovery, filtering, isolation of failures, result aggregation, metadata, duration, and read-only enforcement.
