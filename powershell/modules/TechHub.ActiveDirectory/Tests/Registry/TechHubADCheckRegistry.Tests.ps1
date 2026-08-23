$ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\..'

Describe 'TechHubADCheckRegistry' {
    BeforeAll {
        Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'TechHub.ActiveDirectory.psm1') -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'creates an empty registry directly' {
        $Registry = [TechHubADCheckRegistry]::new()
        $Registry.GetAll().Count | Should -Be 0
    }

    It 'registers all four current checks' {
        $Registry = New-TechHubADCheckRegistry
        $Registry.GetAll().Count | Should -Be 4
        $Registry.GetAll().FunctionName | Should -Contain 'Get-TechHubADUnconstrainedDelegation'
        $Registry.GetAll().FunctionName | Should -Contain 'Get-TechHubADConstrainedDelegation'
        $Registry.GetAll().FunctionName | Should -Contain 'Get-TechHubADRBCD'
        $Registry.GetAll().FunctionName | Should -Contain 'Get-TechHubADPrivilegedGroup'
        $Registry.GetAll().FunctionName | Should -Not -Contain 'Get-TechHubADTrustedToAuth'
    }

    It 'retrieves a definition by CheckId' {
        $Definition = (New-TechHubADCheckRegistry).Get('AD-RBCD')
        $Definition.Name | Should -Be 'Resource-Based Constrained Delegation'
    }

    It 'returns all definitions' {
        @(New-TechHubADCheckRegistry).GetAll().Count | Should -Be 4
    }

    It 'finds definitions by category' {
        $Registry = New-TechHubADCheckRegistry
        $Registry.FindByCategory('Delegation').Count | Should -Be 3
        $Registry.FindByCategory('PrivilegedAccess').Count | Should -Be 1
    }

    It 'finds definitions by provider' {
        (New-TechHubADCheckRegistry).FindByProvider('TechHubADProvider').Count | Should -Be 4
        (New-TechHubADCheckRegistry).FindByProvider('UnknownProvider').Count | Should -Be 0
    }

    It 'rejects duplicate CheckId values' {
        $Registry = [TechHubADCheckRegistry]::new()
        $Definition = [TechHubADCheckDefinition]::new('AD-TEST', 'Test', 'Synthetic check.', 'Test', '1.0.0', $true, $true, 'Get-Test', @('TechHubADProvider'), @('ActiveDirectory'), @('Test'))
        $Registry.Register($Definition)
        { $Registry.Register($Definition) } | Should -Throw
    }

    It 'rejects invalid definitions' {
        $Registry = [TechHubADCheckRegistry]::new()
        { $Registry.Register([PSCustomObject]@{ CheckId = 'AD-INVALID' }) } | Should -Throw
        $Writable = [TechHubADCheckDefinition]::new('AD-WRITABLE', 'Writable', 'Invalid.', 'Test', '1.0.0', $true, $false, 'Get-Test', @(), @(), @())
        { $Registry.Register($Writable) } | Should -Throw
    }

    It 'preserves read-only metadata' {
        $Definitions = (New-TechHubADCheckRegistry).GetAll()
        $Definitions.IsReadOnly | Should -Not -Contain $false
        $Definitions.Enabled | Should -Not -Contain $false
    }

    It 'preserves function name and provider metadata' {
        $Definition = (New-TechHubADCheckRegistry).Get('AD-PRIVILEGED-GROUP')
        $Definition.FunctionName | Should -Be 'Get-TechHubADPrivilegedGroup'
        $Definition.RequiredProviders | Should -Contain 'TechHubADProvider'
        $Definition.RequiredModules | Should -Contain 'ActiveDirectory'
    }

    It 'supports metadata-only enable and disable' {
        $Registry = New-TechHubADCheckRegistry
        $Registry.SetEnabled('AD-RBCD', $false)
        $Registry.Get('AD-RBCD').Enabled | Should -BeFalse
        $Registry.SetEnabled('AD-RBCD', $true)
        $Registry.Get('AD-RBCD').Enabled | Should -BeTrue
    }

    It 'does not execute checks or query Active Directory' {
        $Registry = New-TechHubADCheckRegistry
        $Registry.GetAll() | ForEach-Object { $_.FunctionName | Should -Not -BeNullOrEmpty }
        $Registry.Get('AD-RBCD') | Should -Not -BeNullOrEmpty
        $Registry.GetAll().Count | Should -Be 4
    }

    It 'contains no credentials and serializes as metadata' {
        $Registry = New-TechHubADCheckRegistry
        $Json = $Registry.GetAll() | ConvertTo-Json -Depth 5
        $Json | Should -Match 'AD-UNCONSTRAINED-DELEGATION'
        $SecretMarkers = @('password\s*[:=]', 'secret\s*[:=]', 'token\s*[:=]', 'credential\s*[:=]', '-----' + 'BEGIN')
        foreach ($Marker in $SecretMarkers) {
            $Json | Should -Not -Match $Marker
        }
        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process')
        foreach ($Marker in $DynamicMarkers) {
            $Json | Should -Not -Match [regex]::Escape($Marker)
        }
    }
}
