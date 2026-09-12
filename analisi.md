# Assessment.ActiveDirectory - Pester issue

Provider test isolato:
19/19 PASS.

Suite completa:
2-3 PASS, 16-17 FAIL.

Quindi il provider funziona correttamente da solo, ma la suite completa ha un problema di isolamento/stato condiviso.

Il commit attuale è:
0569250 fix: move AD provider reads to mockable module scope

Il nuovo helper è:
powershell/modules/Assessment.ActiveDirectory/Private/Invoke-AssessmentADProviderReads.ps1

Il provider è:
powershell/modules/Assessment.ActiveDirectory/Providers/ActiveDirectory/AssessmentADProvider.ps1

Analizzare perché i test passano isolatamente ma falliscono nella suite completa.

Controllare soprattutto:
- global Get-AD* functions
- Pester Mock
- module scope
- Import/Remove-Module
- contaminazione tra test

NON modificare subito il production code.

Prima identificare quale test/file causa la contaminazione e spiegare la root cause.

Obiettivo:
far passare tutta la suite mantenendo il provider read-only e mockable.
