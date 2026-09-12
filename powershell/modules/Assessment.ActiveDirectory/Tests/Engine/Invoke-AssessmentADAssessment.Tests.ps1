#requires -Version 5.1

Set-StrictMode -Version Latest

function global:Invoke-TestProviderCheck {
    [CmdletBinding()]
    param(
        [object]$Provider,
        [string]$Server,
        [string]$SearchBase
    )

    [void]$Provider.Seen.Add('first')

    [void]$Provider.Results.Add(
        [PSCustomObject]@{
            Operation  = 'during-check-1'
            Status     = 'Available'
            IsReadOnly = $true
        }
    )

    [PSCustomObject]@{
        FindingId = 'synthetic-first'
        Severity  = 'Low'
        CheckId   = 'AD-SYNTHETIC-FIRST'
    }
}

function global:Invoke-TestProviderCheckTwo {
    [CmdletBinding()]
    param(
        [object]$Provider
    )

    [void]$Provider.Seen.Add('second')

    [void]$Provider.Results.Add(
        [PSCustomObject]@{
            Operation  = 'during-check-2'
            Status     = 'Available'
            IsReadOnly = $true
        }
    )

    [PSCustomObject]@{
        FindingId = 'synthetic-second'
        Severity  = 'High'
        CheckId   = 'AD-SYNTHETIC-SECOND'
    }
}

function global:Invoke-TestLegacyCheck {
    [CmdletBinding()]
    param(
        [string]$Server,
        [string]$SearchBase
    )

    [PSCustomObject]@{
        FindingId = 'synthetic-legacy'
        Severity  = 'Low'
        CheckId   = 'AD-SYNTHETIC-LEGACY'
    }
}

function global:Invoke-TestThrowingCheck {
    [CmdletBinding()]
    param()

    throw 'Synthetic check failure'
}

Describe 'Invoke-AssessmentADAssessment provider lifecycle' {

    BeforeAll {

        $ModuleRoot = Join-Path `
            (Get-Location).Path `
            'powershell\modules\Assessment.ActiveDirectory'

        $ModuleManifest = Join-Path `
            $ModuleRoot `
            'Assessment.ActiveDirectory.psd1'

        if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf)) {
            throw "Assessment.ActiveDirectory manifest not found: $ModuleManifest"
        }

        Remove-Module `
            Assessment.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue

        Import-Module `
            $ModuleManifest `
            -Force `
            -ErrorAction Stop
    }

    AfterAll {

        Remove-Item `
            Function:\Invoke-TestProviderCheck `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Invoke-TestProviderCheckTwo `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Invoke-TestLegacyCheck `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Invoke-TestThrowingCheck `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Module `
            Assessment.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue
    }

    BeforeEach {

        $Script:Provider = [PSCustomObject]@{
            Server  = $null
            Seen    = New-Object System.Collections.ArrayList
            Results = New-Object System.Collections.ArrayList
        }

        Add-Member `
            -InputObject $Script:Provider `
            -MemberType ScriptMethod `
            -Name GetProviderStatus `
            -Value {
                [PSCustomObject]@{
                    Status = 'Available'
                }
            }

        $Script:ProviderCreateCount = 0

        $Script:Registry = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckRegistry]::new()
        }
    }

    It 'does not create a provider when no selected check requires one' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-LEGACY',
                'Legacy',
                'Legacy check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestLegacyCheck',
                @(),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Script:ProviderCreateCount |
            Should -Be 0

        $Result.Findings.Count |
            Should -Be 1
    }

    It 'creates exactly one provider for one provider-aware check' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Script:ProviderCreateCount |
            Should -Be 1

        $Result.Findings.Count |
            Should -Be 1
    }

    It 'reuses the exact same provider instance across provider-aware checks' {

        $DefinitionOne = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $DefinitionTwo = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-SECOND',
                'Second',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheckTwo',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($DefinitionOne)
        $Script:Registry.Register($DefinitionTwo)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Script:ProviderCreateCount |
            Should -Be 1

        $Script:Provider.Seen.Count |
            Should -Be 2

        $Result.ProviderResults.Count |
            Should -Be 2
    }

    It 'reuses an explicitly supplied provider without creating another' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++

            return [PSCustomObject]@{
                Server  = $null
                Seen    = New-Object System.Collections.ArrayList
                Results = New-Object System.Collections.ArrayList
            }
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry `
            -Provider $Script:Provider

        $Script:ProviderCreateCount |
            Should -Be 0

        $Script:Provider.Seen |
            Should -Contain 'first'

        $Result.ProviderResults[0].Operation |
            Should -Be 'during-check-1'
    }

    It 'does not pass Provider to a legacy check' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-LEGACY',
                'Legacy',
                'Legacy check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestLegacyCheck',
                @(),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry `
            -Provider $Script:Provider

        $Result.Findings.Count |
            Should -Be 1
    }

    It 'passes Server and SearchBase only to supported parameters' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        Invoke-AssessmentADAssessment `
            -Registry $Script:Registry `
            -Server 'dc01.example.test' `
            -SearchBase 'DC=example,DC=test' |
            Out-Null

        $Script:ProviderCreateCount |
            Should -Be 1

        $Script:Provider.Seen |
            Should -Contain 'first'
    }

    It 'preserves CheckId and category filtering' {

        $DefinitionOne = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $DefinitionTwo = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-SECOND',
                'Second',
                'Provider check.',
                'Health',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheckTwo',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($DefinitionOne)
        $Script:Registry.Register($DefinitionTwo)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $ResultById = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry `
            -CheckId 'AD-FIRST'

        $ResultById.Findings[0].CheckId |
            Should -Be 'AD-SYNTHETIC-FIRST'

        $ResultByCategory = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry `
            -Category 'Health'

        $ResultByCategory.Findings[0].CheckId |
            Should -Be 'AD-SYNTHETIC-SECOND'
    }

    It 'skips disabled checks and enforces read-only metadata' {

        $DisabledDefinition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $false,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($DisabledDefinition)

        $Writable = [PSCustomObject]@{
            CheckId           = 'AD-WRITABLE'
            Name              = 'Writable'
            Description       = 'Invalid'
            Category          = 'Security'
            Version           = '1.0.0'
            Enabled           = $true
            IsReadOnly        = $false
            FunctionName      = 'Invoke-TestProviderCheck'
            RequiredProviders = @()
            RequiredModules   = @()
            Tags              = @()
        }

        [void]$Script:Registry.Definitions.Add($Writable)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Result.Summary.ChecksSkipped |
            Should -Be 1

        $Result.Summary.ChecksFailed |
            Should -Be 1

        $ErrorResult = $Result.Metadata.CheckResults |
            Where-Object CheckId -eq 'AD-WRITABLE'

        $ErrorResult.ErrorType |
            Should -Be 'ReadOnlyViolation'
    }

    It 'records provider creation failure without fabricating findings' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            throw 'Synthetic provider creation failure'
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Result.Findings.Count |
            Should -Be 0

        $Result.Summary.ChecksFailed |
            Should -Be 1

        $ErrorResult = $Result.Metadata.CheckResults[0]

        $ErrorResult.CheckId |
            Should -Be 'AD-FIRST'

        $ErrorResult.ErrorType |
            Should -Be 'ProviderCreationError'
    }

    It 'isolates check failures and preserves unrelated findings' {

        $DefinitionOne = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $DefinitionTwo = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-THROW',
                'Throwing',
                'Throwing check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestThrowingCheck',
                @(),
                @(),
                @()
            )
        }

        $Script:Registry.Register($DefinitionOne)
        $Script:Registry.Register($DefinitionTwo)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Result.Findings.Count |
            Should -Be 1

        $Result.Summary.ChecksFailed |
            Should -Be 1

        $ErrorResult = $Result.Metadata.CheckResults |
            Where-Object CheckId -eq 'AD-THROW'

        $ErrorResult.ErrorType |
            Should -Be 'CheckExecutionError'
    }

    It 'captures provider results generated during check execution' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Result.ProviderResults.Count |
            Should -Be 1

        $Result.ProviderResults[0].Operation |
            Should -Be 'during-check-1'
    }

    It 'completes AssessmentResult metadata and summary' {

        $Definition = & (Get-Module Assessment.ActiveDirectory) {
            [AssessmentADCheckDefinition]::new(
                'AD-FIRST',
                'First',
                'Provider check.',
                'Security',
                '1.0.0',
                $true,
                $true,
                'Invoke-TestProviderCheck',
                @('AssessmentADProvider'),
                @(),
                @()
            )
        }

        $Script:Registry.Register($Definition)

        Mock New-AssessmentADProvider -ModuleName Assessment.ActiveDirectory {
            $Script:ProviderCreateCount++
            return $Script:Provider
        }

        $Result = Invoke-AssessmentADAssessment `
            -Registry $Script:Registry

        $Result.AssessmentId |
            Should -Not -BeNullOrEmpty

        $Result.StartedAt |
            Should -Not -BeNullOrEmpty

        $Result.CompletedAt |
            Should -Not -BeNullOrEmpty

        $Result.Duration |
            Should -Not -BeNullOrEmpty

        $Result.Summary.FindingsCount |
            Should -Be 1

        $Result.DataAvailability |
            Should -Be 'Complete'
    }

    It 'contains no direct AD modifications or dynamic execution' {

        $ModuleRoot = Join-Path `
            (Get-Location).Path `
            'powershell\modules\Assessment.ActiveDirectory'

        $EnginePath = Join-Path `
            $ModuleRoot `
            'Public\Invoke-AssessmentADAssessment.ps1'

        if (-not (Test-Path -LiteralPath $EnginePath -PathType Leaf)) {
            throw "Engine source file not found: $EnginePath"
        }

        $Source = Get-Content `
            -LiteralPath $EnginePath `
            -Raw

        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' |
            Should -BeFalse

        $DynamicMarkers = @(
            'Invoke-Expression'
            'ScriptBlock'
            'Start-Process'
        )

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) |
                Should -BeFalse
        }
    }
}