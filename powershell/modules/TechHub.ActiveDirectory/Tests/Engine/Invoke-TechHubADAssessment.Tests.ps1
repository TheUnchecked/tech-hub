$ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\..'

function New-TestEngineProvider {
    $Provider = [PSCustomObject]@{
        Server = $null
        Seen = New-Object System.Collections.ArrayList
        Results = New-Object System.Collections.ArrayList
    }
    Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetProviderStatus -Value {
        if ($this.Results.Count -gt 0) { return [PSCustomObject]@{ Status = 'Available' } }
        [PSCustomObject]@{ Status = 'Available' }
    }
    $Provider
}

function global:Invoke-TestProviderCheck {
    [CmdletBinding()]
    param([object]$Provider, [string]$Server, [string]$SearchBase)
    [void]$Provider.Seen.Add('first')
    [void]$Provider.Results.Add([PSCustomObject]@{ Operation = 'during-check-1'; Status = 'Available'; IsReadOnly = $true })
    [PSCustomObject]@{ FindingId = 'synthetic-first'; Severity = 'Low'; CheckId = 'AD-SYNTHETIC-FIRST' }
}

function global:Invoke-TestProviderCheckTwo {
    [CmdletBinding()]
    param([object]$Provider)
    [void]$Provider.Seen.Add('second')
    [void]$Provider.Results.Add([PSCustomObject]@{ Operation = 'during-check-2'; Status = 'Available'; IsReadOnly = $true })
    [PSCustomObject]@{ FindingId = 'synthetic-second'; Severity = 'High'; CheckId = 'AD-SYNTHETIC-SECOND' }
}

function global:Invoke-TestLegacyCheck {
    [CmdletBinding()]
    param([string]$Server, [string]$SearchBase)
    [PSCustomObject]@{ FindingId = 'synthetic-legacy'; Severity = 'Low'; CheckId = 'AD-SYNTHETIC-LEGACY' }
}

function global:Invoke-TestThrowingCheck {
    [CmdletBinding()]
    param()
    throw 'Synthetic check failure'
}

Describe 'Invoke-TechHubADAssessment provider lifecycle' {
    BeforeAll {
        Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'TechHub.ActiveDirectory.psm1') -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Item Function:\Invoke-TestProviderCheck -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Invoke-TestProviderCheckTwo -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Invoke-TestLegacyCheck -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Invoke-TestThrowingCheck -Force -ErrorAction SilentlyContinue
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:Provider = New-TestEngineProvider
        $Script:ProviderCreateCount = 0
        $Script:Registry = [TechHubADCheckRegistry]::new()
    }

    It 'does not create a provider when no selected check requires one' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-LEGACY', 'Legacy', 'Legacy check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestLegacyCheck', @(), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Script:ProviderCreateCount | Should -Be 0
        $Result.Findings.Count | Should -Be 1
    }

    It 'creates exactly one provider for one provider-aware check' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Script:ProviderCreateCount | Should -Be 1
        $Result.Findings.Count | Should -Be 1
    }

    It 'reuses the exact same provider instance across provider-aware checks' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-SECOND', 'Second', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheckTwo', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Script:ProviderCreateCount | Should -Be 1
        $Script:Provider.Seen.Count | Should -Be 2
        $Result.ProviderResults.Count | Should -Be 2
    }

    It 'reuses an explicitly supplied provider without creating another' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; New-TestEngineProvider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry -Provider $Script:Provider
        $Script:ProviderCreateCount | Should -Be 0
        $Script:Provider.Seen | Should -Contain 'first'
        $Result.ProviderResults[0].Operation | Should -Be 'during-check-1'
    }

    It 'does not pass Provider to a legacy check' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-LEGACY', 'Legacy', 'Legacy check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestLegacyCheck', @(), @(), @()))
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry -Provider $Script:Provider
        $Result.Findings.Count | Should -Be 1
    }

    It 'passes Server and SearchBase only to supported parameters' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        Invoke-TechHubADAssessment -Registry $Script:Registry -Server 'dc01.example.test' -SearchBase 'DC=example,DC=test' | Out-Null
        $Script:ProviderCreateCount | Should -Be 1
        $Script:Provider.Seen | Should -Contain 'first'
    }

    It 'preserves CheckId and category filtering' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-SECOND', 'Second', 'Provider check.', 'Health', '1.0.0', $true, $true, 'Invoke-TestProviderCheckTwo', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        (Invoke-TechHubADAssessment -Registry $Script:Registry -CheckId 'AD-FIRST').Findings[0].CheckId | Should -Be 'AD-SYNTHETIC-FIRST'
        (Invoke-TechHubADAssessment -Registry $Script:Registry -Category 'Health').Findings[0].CheckId | Should -Be 'AD-SYNTHETIC-SECOND'
    }

    It 'skips disabled checks and enforces read-only metadata' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $false, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        $Writable = [PSCustomObject]@{ CheckId = 'AD-WRITABLE'; Name = 'Writable'; Description = 'Invalid'; Category = 'Security'; Version = '1.0.0'; Enabled = $true; IsReadOnly = $false; FunctionName = 'Invoke-TestProviderCheck'; RequiredProviders = @(); RequiredModules = @(); Tags = @() }
        $Script:Registry.Definitions.Add($Writable) | Out-Null
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Result.Summary.ChecksSkipped | Should -Be 1
        $Result.Summary.ChecksFailed | Should -Be 1
        ($Result.Metadata.CheckResults | Where-Object CheckId -eq 'AD-WRITABLE').ErrorType | Should -Be 'ReadOnlyViolation'
    }

    It 'records provider creation failure without fabricating findings' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { throw 'Synthetic provider creation failure' }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Result.Findings.Count | Should -Be 0
        $Result.Summary.ChecksFailed | Should -Be 1
        $ErrorResult = $Result.Metadata.CheckResults[0]
        $ErrorResult.CheckId | Should -Be 'AD-FIRST'
        $ErrorResult.ErrorType | Should -Be 'ProviderCreationError'
    }

    It 'isolates check failures and preserves unrelated findings' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-THROW', 'Throwing', 'Throwing check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestThrowingCheck', @(), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Result.Findings.Count | Should -Be 1
        $Result.Summary.ChecksFailed | Should -Be 1
        ($Result.Metadata.CheckResults | Where-Object CheckId -eq 'AD-THROW').ErrorType | Should -Be 'CheckExecutionError'
    }

    It 'captures provider results generated during check execution' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Result.ProviderResults.Count | Should -Be 1
        $Result.ProviderResults[0].Operation | Should -Be 'during-check-1'
    }

    It 'completes AssessmentResult metadata and summary' {
        $Script:Registry.Register([TechHubADCheckDefinition]::new('AD-FIRST', 'First', 'Provider check.', 'Security', '1.0.0', $true, $true, 'Invoke-TestProviderCheck', @('TechHubADProvider'), @(), @()))
        Mock New-TechHubADProvider -ModuleName TechHub.ActiveDirectory { $Script:ProviderCreateCount++ ; $Script:Provider }
        $Result = Invoke-TechHubADAssessment -Registry $Script:Registry
        $Result.AssessmentId | Should -Not -BeNullOrEmpty
        $Result.StartedAt | Should -Not -BeNullOrEmpty
        $Result.CompletedAt | Should -Not -BeNullOrEmpty
        $Result.Duration | Should -Not -BeNullOrEmpty
        $Result.Summary.FindingsCount | Should -Be 1
        $Result.DataAvailability | Should -Be 'Complete'
    }

    It 'contains no direct AD modifications or dynamic execution' {
        $Source = Get-Content -Path (Join-Path $ModuleRoot 'Public\Invoke-TechHubADAssessment.ps1') -Raw
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process')
        foreach ($Marker in $DynamicMarkers) { $Source -match [regex]::Escape($Marker) | Should -BeFalse }
    }
}
