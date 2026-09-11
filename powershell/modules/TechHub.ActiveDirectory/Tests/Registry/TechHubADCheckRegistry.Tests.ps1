#requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'TechHubADCheckRegistry' {

    BeforeAll {

        $ModuleRoot = (Resolve-Path "$PSScriptRoot/../..").Path
        $ModuleManifest = Join-Path $ModuleRoot 'TechHub.ActiveDirectory.psd1'

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

        $Module = Get-Module TechHub.ActiveDirectory

        $Module |
            Should -Not -BeNullOrEmpty

        & $Module {

            $Registry = [TechHubADCheckRegistry]::new()

            $Registry.GetAll().Count |
                Should -Be 0
        }
    }

    It 'registers all five current checks' {

        $Registry = New-AssessmentADCheckRegistry

        $Registry |
            Should -Not -BeNullOrEmpty

        $Registry.GetAll().Count |
            Should -Be 5

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-AssessmentADUnconstrainedDelegation'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-AssessmentADConstrainedDelegation'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-AssessmentADRBCD'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-AssessmentADPrivilegedGroup'

        $Registry.GetAll().FunctionName |
            Should -Contain 'Get-AssessmentADRemoteLocalGroups'

        $Registry.GetAll().FunctionName |
            Should -Not -Contain 'Get-AssessmentADTrustedToAuth'
    }

    It 'retrieves a definition by CheckId' {

        $Registry = New-AssessmentADCheckRegistry

        $Definition = $Registry.Get('AD-RBCD')

        $Definition |
            Should -Not -BeNullOrEmpty

        $Definition.Name |
            Should -Be 'Resource-Based Constrained Delegation'
    }

    It 'returns all definitions' {

        $Registry = New-AssessmentADCheckRegistry

        @($Registry.GetAll()).Count |
            Should -Be 5
    }

    It 'finds definitions by category' {

        $Registry = New-AssessmentADCheckRegistry

        @($Registry.FindByCategory('Delegation')).Count |
            Should -Be 3

        @($Registry.FindByCategory('PrivilegedAccess')).Count |
            Should -Be 2
    }

    It 'finds definitions by provider' {

        $Registry = New-AssessmentADCheckRegistry

        $Definitions = @(
            $Registry.FindByProvider('TechHubADProvider')
        )

        $Definitions.Count |
            Should -Be 4
    }

    It 'returns null for an unknown CheckId' {

        $Registry = New-AssessmentADCheckRegistry

        $Definition = $Registry.Get('AD-DOES-NOT-EXIST')

        $Definition |
            Should -BeNullOrEmpty
    }

    It 'does not return disabled checks by default' {

        $Registry = New-AssessmentADCheckRegistry

        $EnabledDefinitions = @(
            $Registry.GetAll() |
                Where-Object { $_.Enabled }
        )

        $EnabledDefinitions.Count |
            Should -Be 5
    }

    It 'preserves read-only metadata' {

        $Registry = New-AssessmentADCheckRegistry

        $Registry.GetAll() |
            ForEach-Object {
                $_.IsReadOnly |
                    Should -BeTrue
            }
    }

    It 'rejects duplicate CheckId values' {

        $Module = Get-Module TechHub.ActiveDirectory

        $Module |
            Should -Not -BeNullOrEmpty

        & $Module {

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

            $Thrown = $false

            try {
                $Registry.Register($Definition)
            }
            catch {
                $Thrown = $true
            }

            $Thrown |
                Should -BeTrue
        }
    }

    It 'rejects invalid definitions' {

        $Module = Get-Module TechHub.ActiveDirectory

        $Module |
            Should -Not -BeNullOrEmpty

        & $Module {

            $Registry = [TechHubADCheckRegistry]::new()

            $Thrown = $false

            try {
                $Registry.Register(
                    [PSCustomObject]@{
                        CheckId = 'AD-INVALID'
                    }
                )
            }
            catch {
                $Thrown = $true
            }

            $Thrown |
                Should -BeTrue
        }
    }

    It 'rejects null definitions' {

        $Module = Get-Module TechHub.ActiveDirectory

        $Module |
            Should -Not -BeNullOrEmpty

        & $Module {

            $Registry = [TechHubADCheckRegistry]::new()

            $Thrown = $false

            try {
                $Registry.Register($null)
            }
            catch {
                $Thrown = $true
            }

            $Thrown |
                Should -BeTrue
        }
    }

    It 'preserves registration order' {

        $Registry = New-AssessmentADCheckRegistry

        $Ids = @(
            $Registry.GetAll().CheckId
        )

        $Ids[0] |
            Should -Be 'AD-UNCONSTRAINED-DELEGATION'

        $Ids[1] |
            Should -Be 'AD-CONSTRAINED-DELEGATION'

        $Ids[2] |
            Should -Be 'AD-RBCD'

        $Ids[3] |
            Should -Be 'AD-PRIVILEGED-GROUP'

        $Ids[4] |
            Should -Be 'AD-REMOTE-LOCAL-GROUPS'
    }
}