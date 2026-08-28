# TechHub.ActiveDirectory - Copilot Instructions

## Project

TechHub.ActiveDirectory is a reusable PowerShell 5.1 framework for
read-only Active Directory Security Assessment and Remote Windows Assessment.

The project must remain modular, reusable and safe.

## PowerShell

Target PowerShell 5.1.

Use:

#Requires -Version 5.1
Set-StrictMode -Version Latest

Do not introduce PowerShell 7-only features unless explicitly requested.

## Read-only

ALL assessment functionality must be read-only.

Never modify:

- Active Directory objects
- group membership
- registry
- scheduled tasks
- services
- local groups
- firewall
- WinRM
- security configuration
- system configuration

The framework collects and analyzes data only.

## Architecture

Keep these components separated:

- Assessment Engine
- Check Registry
- Check Definitions
- Assessment Results
- Findings
- AD Provider
- Remote Transport
- Collectors
- Exporters
- Tests

Avoid unnecessary coupling.

## AD Security Assessment

AD Security checks may use the Active Directory provider.

Examples:

- Unconstrained Delegation
- Constrained Delegation
- RBCD
- Privileged Groups
- Service Accounts

These checks belong to the AD Security Assessment domain.

## Remote Assessment

Remote checks inspect Windows computers.

Examples:

- Remote OS
- Remote Local Groups
- Remote Scheduled Tasks
- Remote IIS Application Pools
- Remote Network Shares
- Remote Windows Features

Remote checks must not require a Domain Controller unless AD data is
actually required by the check.

Use the existing remote transport abstraction whenever possible.

## Tiering

Tiering is NOT part of the current module.

Do not introduce:

- Tier 0
- Tier 1
- Tier 2
- Tier violations

into the current AD Security or Remote Assessment modules.

Tiering will be implemented later as a separate module.

## Check Registry

Every assessment check must have:

- unique CheckId
- name
- description
- category
- version
- enabled state
- IsReadOnly metadata
- function name
- dependencies
- tags

A new check must be registered in the Check Registry.

Do not duplicate registry definitions unnecessarily.

## Findings

Findings should maintain the existing finding contract.

Important properties include:

- AssessmentId
- CheckId
- CheckName
- FindingId
- Title
- Description
- Category
- Severity
- Confidence
- Status
- AffectedObject
- ObjectType
- DistinguishedName
- SamAccountName
- ObjectGuid
- Evidence
- Risk
- Recommendation
- References
- CollectedAt
- Domain
- Forest
- DomainController
- IsReadOnly

Do not introduce alternative finding schemas without a strong reason.

## Assessment Result

The assessment engine uses:

TechHubADAssessmentResult

Do not break the existing result contract.

The result contains:

- Metadata
- Summary
- Findings
- Observations
- Inventory
- Health
- ProviderResults

## Providers

AD checks may use:

TechHubADProvider

Remote checks should use the existing remote transport helpers.

Do not duplicate transport implementations unnecessarily.

## Remote Transport

Preferred transport:

1. CIM / WSMan
2. CIM / DCOM

Transport failures must be represented explicitly.

Do not treat unavailable data as a successful security result.

## Error Handling

Distinguish between:

- Success
- NoData
- NotAvailable
- AccessDenied
- AuthenticationFailure
- LDAP failure
- WinRM failure
- RPC failure
- Provider failure
- CheckExecutionError

Never silently convert an error into a security finding.

## StrictMode

Because Set-StrictMode -Version Latest is used, never assume that
optional properties exist.

Before accessing optional properties, verify that they exist.

Normalized objects should expose a stable schema.

Unavailable values should normally be represented by $null.

## AD Object Normalization

Never allow placeholder values such as:

string
System.String

to become Active Directory identities.

Use real:

- DistinguishedName
- SamAccountName
- SID
- ObjectGUID

when resolving AD objects.

## Group Membership

Recursive group membership must:

- support direct membership
- support indirect membership
- preserve membership path
- detect circular nesting
- prevent duplicate traversal
- resolve users
- resolve computers
- resolve groups
- normalize returned objects

Do not use placeholder identities.

## Security

This is security assessment software.

When reviewing code, prioritize:

- correctness
- security
- false positives
- false negatives
- privilege escalation paths
- credential handling
- authentication
- authorization
- remoting security
- command injection
- path manipulation
- unsafe dynamic execution
- accidental write operations
- sensitive data exposure

Security conclusions must be evidence-based.

## False Positives

Never invent evidence.

If information cannot be collected, report the appropriate unavailable
state instead of guessing.

Prefer:

Unknown

or:

NotAvailable

over assumptions.

## Changes

Before modifying existing code:

1. Inspect callers.
2. Inspect the Registry definition.
3. Inspect related private helpers.
4. Inspect related tests.
5. Preserve the public contract.

Prefer targeted fixes over unnecessary refactoring.

Do not modify unrelated files.

## Testing

Use Pester.

New functionality should include tests for:

- normal operation
- empty results
- unavailable data
- access denied
- invalid input
- missing properties
- recursive groups
- circular groups
- disabled accounts
- provider failures
- remote transport failures

## Copilot Code Review

When reviewing code:

1. Prioritize correctness over style.
2. Identify security issues.
3. Identify PowerShell 5.1 compatibility problems.
4. Identify StrictMode problems.
5. Identify read-only violations.
6. Identify false-positive risks.
7. Identify false-negative risks.
8. Identify breaking changes.
9. Check registry integration.
10. Check test coverage.

Do not approve code simply because it works in one environment.

## Development Philosophy

TechHub.ActiveDirectory is a framework, not a monolithic script.

New functionality should normally be implemented as:

- Check
- Collector
- Provider functionality
- Transport helper
- Exporter
- Module

depending on its responsibility.

Keep responsibilities separated.

## Current Priorities

Current priorities are:

1. Stabilize Core Engine.
2. Stabilize AD Security checks.
3. Stabilize Remote Assessment checks.
4. Validate registered checks.
5. Improve assessment profiles.
6. Add additional checks.
7. Implement Tiering later as a separate module.

Do not implement Tiering unless explicitly requested.