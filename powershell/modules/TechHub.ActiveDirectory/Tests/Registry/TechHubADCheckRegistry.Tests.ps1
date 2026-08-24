#requires -Version 5.1

Set-StrictMode -Version Latest

$ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ModuleManifest = Join-Path $ModuleRoot 'TechHub.ActiveDirectory.psd1'

Describe 'TechHubADCheckRegistry' {

    BeforeAll {
        if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf)) {
            throw "TechHub.ActiveDirectory module manifest not found: $ModuleManifest"
        }

        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue

        Import-Module $ModuleManifest -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'creates an empty registry directly' {
        & (Get-Module TechHub.ActiveDirectory) {
            $Registry = [TechHubADCheckRegistry]::new()

            $Registry.GetAll().Count |
                Should -Be 0
        }
    }

    It 'registers all four current checks' {
        $Registry = New-TechHubADCheckRegistry

        $Registry.GetAll().Count |
            Should -Be 4

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-TechHubADUnconstrainedDelegation'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-TechHubADConstrainedDelegation'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-TechHubADRBCD'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-TechHubADPrivilegedGroup'

        $Registry.GetAll().FunctionName |
            Should -Not -Contain 'Get-TechHubADTrustedToAuth'
    }

    It 'retrieves a definition by CheckId' {
        $Definition = (New-TechHubADCheckRegistry).Get('AD-RBCD')

        $Definition |
            Should -Not -BeNullOrEmpty

        $Definition.Name |
            Should -Be 'Resource-Based Constrained Delegation'
    }

    It 'returns all definitions' {
        @(New-TechHubADCheckRegistry).GetAll().Count |
            Should -Be 4
    }

    It 'finds definitions by category' {
        $Registry = New-TechHubADCheckRegistry

        $Registry.FindByCategory('Delegation').Count |
            Should -Be 3

        $Registry.FindByCategory('PrivilegedAccess').Count |
            Should -Be 1
    }

    It 'finds definitions by provider' {
        $Registry = New-TechHubADCheckRegistry

        $Registry.FindByProvider('TechHubADProvider').Count |
            Should -Be 4

        $Registry.FindByProvider('UnknownProvider').Count |
            Should -Be 0
    }

    It 'rejects duplicate CheckId values' {
        & (Get-Module TechHub.ActiveDirectory) {
            $Registry = [TechHubADCheckRegistry]::new()

            $Definition = [TechHubADCheckDefinition]::new(
                'AD-TEST',
                'Test',
                'Synthetic check.',
                'Test',
                '1.0.0',
                $true,
                $true,
                'Get-Test',
                @('TechHubADProvider'),
                @('ActiveDirectory'),
                @('Test')
            )

            $Registry.Register($Definition)

            {
                $Registry.Register($Definition)
            } |
                Should -Throw
        }
    }

    It 'rejects invalid definitions' {
        & (Get-Module TechHub.ActiveDirectory) {
            $Registry = [TechHubADCheckRegistry]::new()

            {
                $Registry.Register(
                    [PSCustomObject]@{
                        CheckId = 'AD-INVALID'
                    }
                )
            } |
                Should -Throw

            $Writable = [TechHubADCheckDefinition]::new(
                'AD-WRITABLE',
                'Writable',
                'Invalid.',
                'Test',
                '1.0.0',
                $true,
                $false,
                'Get-Test',
                @(),
                @(),
                @()
            )

            {
                $Registry.Register($Writable)
            } |
                Should -Throw
        }
    }

    It 'preserves read-only metadata' {
        $Definitions = (New-TechHubADCheckRegistry).GetAll()

        @(
            $Definitions |
                Where-Object {
                    $_.IsReadOnly -ne $true
                }
        ).Count |
            Should -Be 0

        @(
            $Definitions |
                Where-Object {
                    $_.Enabled -ne $true
                }
        ).Count |
            Should -Be 0
    }

    It 'preserves function name and provider metadata' {
        $Definition = (New-TechHubADCheckRegistry).Get('AD-PRIVILEGED-GROUP')

        $Definition |
            Should -Not -BeNullOrEmpty

        $Definition.FunctionName |
            Should -Be 'Get-TechHubADPrivilegedGroup'

        $Definition.RequiredProviders |
            Should -Contain 'TechHubADProvider'

        $Definition.RequiredModules |
            Should -Contain 'ActiveDirectory'
    }

    It 'supports metadata-only enable and disable' {
        $Registry = New-TechHubADCheckRegistry

        $Registry.SetEnabled('AD-RBCD', $false)

        $Registry.Get('AD-RBCD').Enabled |
            Should -BeFalse

        $Registry.SetEnabled('AD-RBCD', $true)

        $Registry.Get('AD-RBCD').Enabled |
            Should -BeTrue
    }

    It 'does not execute checks or query Active Directory' {
        $Registry = New-TechHubADCheckRegistry

        $Registry.GetAll() |
            ForEach-Object {
                $_.FunctionName |
                    Should -Not -BeNullOrEmpty
            }

        $Registry.Get('AD-RBCD') |
            Should -Not -BeNullOrEmpty

        $Registry.GetAll().Count |
            Should -Be 4
    }

    It 'contains no credentials and serializes as metadata' {
        $Registry = New-TechHubADCheckRegistry

        $Json = $Registry.GetAll() |
            ConvertTo-Json -Depth 5

        $Json |
            Should -Match 'AD-UNCONSTRAINED-DELEGATION'

        $SecretMarkers = @(
            'password\s*[:=]'
            'secret\s*[:=]'
            'token\s*[:=]'
            'credential\s*[:=]'
            '-----BEGIN'
        )

        foreach ($Marker in $SecretMarkers) {
            $Json |
                Should -Not -Match $Marker
        }

        $DynamicMarkers = @(
            'Invoke-Expression'
            'ScriptBlock'
            'Start-Process'
        )

        foreach ($Marker in $DynamicMarkers) {
            $Json |
                Should -Not -Match ([regex]::Escape($Marker))
        }
    }
}