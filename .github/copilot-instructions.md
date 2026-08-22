# Tech Hub — Copilot Instructions

## General principles

- Prefer simple, maintainable and reusable solutions.
- Follow security-by-design principles.
- Never expose credentials, secrets, tokens or sensitive information.
- Do not hardcode passwords, API keys or connection strings.
- Explain important security implications when relevant.
- Prefer automation over repetitive manual operations.
- Avoid unnecessary dependencies.

## PowerShell

- Prefer PowerShell 7 when compatible with the target environment.
- Write scripts that are readable, modular and reusable.
- Use approved PowerShell verbs.
- Use parameters instead of hardcoded values.
- Validate input parameters.
- Handle errors explicitly.
- Use `try/catch/finally` when appropriate.
- Prefer structured output over formatted console output when the result may be consumed by another tool.
- Add logging when appropriate.
- Make scripts idempotent whenever possible.
- Include comment-based help for reusable scripts.

## Microsoft environments

When working with:

- Active Directory
- Windows Server
- Microsoft 365
- Entra ID
- DNS
- DHCP
- Group Policy
- SQL Server

consider security, permissions, least privilege, compatibility and operational impact.

## Documentation

Documentation should explain:

1. Purpose
2. Requirements
3. Parameters
4. Usage
5. Expected output
6. Errors and troubleshooting
7. Security considerations

Use Markdown.

## Code quality

Before proposing code:

- Check for obvious security issues.
- Check error handling.
- Check compatibility.
- Avoid unnecessary complexity.
- Prefer existing repository components when they can be reused.

## Secrets

Never create or commit:

- passwords
- API keys
- access tokens
- private keys
- certificates containing private keys
- production credentials
- sensitive configuration files

Use placeholders or environment variables instead.

## Communication

Be concise and technically precise.

When there are multiple valid approaches, explain the trade-offs and recommend one.
