#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRecycleBinStatus' {

    BeforeAll {

        $script:TestFile = $PSCommandPath
        $script:TestsRoot = Split-Path -Parent $script:TestFile
        $script:ModuleRoot = Split-Path -Parent $script:TestsRoot

        $script:ModulePath = Join-Path `
            -Path $script:ModuleRoot `
            -ChildPath 'TechHub.ActiveDirectory.psm1'

        Import-Module `
            -Name $script:ModulePath `
            -Force `
            -ErrorAction Stop

        $script:NewTestRecycleBinProvider = {
            param (
                [string]$Status = 'Available',
                [object[]]$Data = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $Provider = [PSCustomObject]@{
                Server        = $null
                DomainResult  = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ DNSRoot = 'example.test' }) }
                ForestResult  = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ Name = 'example.test' }) }
                FeaturesResult = [PSCustomObject]@{ Status = $Status; Data = @($Data); ErrorType = $ErrorType; ErrorMessage = $ErrorMessage }
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetOptionalFeatures -Value {
                param($Filter)
                return $this.FeaturesResult
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'reports Informational when the Recycle Bin is enabled' {
        $Feature = [PSCustomObject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @('DC=example,DC=test') }

        $Result = @(Get-AssessmentADRecycleBinStatus -Provider (& $script:NewTestRecycleBinProvider -Data @($Feature)))[0]

        $Result.CheckId | Should -Be 'AD-RECYCLE-BIN'
        $Result.Category | Should -Be 'DisasterRecovery'
        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.RecycleBinEnabled | Should -BeTrue
    }

    It 'reports Medium when the feature exists but is not enabled anywhere' {
        $Feature = [PSCustomObject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @() }

        $Result = @(Get-AssessmentADRecycleBinStatus -Provider (& $script:NewTestRecycleBinProvider -Data @($Feature)))[0]

        $Result.Severity | Should -Be 'Medium'
        $Result.Evidence.RecycleBinEnabled | Should -BeFalse
    }

    It 'reports Medium when the feature cannot be found at all' {
        $Result = @(Get-AssessmentADRecycleBinStatus -Provider (& $script:NewTestRecycleBinProvider -Data @()))[0]

        $Result.Severity | Should -Be 'Medium'
        $Result.Title | Should -Be 'Recycle Bin feature not found'
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Result = @(
            Get-AssessmentADRecycleBinStatus -Provider (
                & $script:NewTestRecycleBinProvider -Status 'Error' -ErrorType 'AccessDenied' -ErrorMessage 'Synthetic failure'
            )
        )[0]

        $Result.Status | Should -Be 'Error'
        $Result.Evidence.ErrorType | Should -Be 'AccessDenied'
    }

    It 'creates a provider when invoked without one' {
        $Feature = [PSCustomObject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @('DC=example,DC=test') }

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestRecycleBinProvider -Data @($Feature)
        }

        $Results = @(Get-AssessmentADRecycleBinStatus -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Feature = [PSCustomObject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @('DC=example,DC=test') }

        $Result = @(Get-AssessmentADRecycleBinStatus -Provider (& $script:NewTestRecycleBinProvider -Data @($Feature)))[0]

        @(
            'AssessmentId', 'CheckId', 'CheckName', 'FindingId', 'Title', 'Description',
            'Category', 'Severity', 'Confidence', 'Status', 'AffectedObject', 'ObjectType',
            'DistinguishedName', 'SamAccountName', 'ObjectGuid', 'Evidence', 'Risk',
            'Recommendation', 'References', 'CollectedAt', 'Domain', 'Forest',
            'DomainController', 'IsReadOnly'
        ) | ForEach-Object {
            $Result.PSObject.Properties.Name | Should -Contain $_
        }

        $Result.IsReadOnly | Should -BeTrue
    }

    It 'contains no direct AD cmdlets, modification cmdlets, or dynamic execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADRecycleBinStatus.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
