#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADKrbtgtPasswordAge' {

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

        $script:NewTestKrbtgtProviderResult = {
            param (
                [string]$Status = 'Available',
                [object[]]$Data = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            [PSCustomObject][ordered]@{
                Provider     = 'TechHubADProvider'
                Operation    = 'GetADObjects'
                Status       = $Status
                Data         = @($Data)
                ErrorType    = $ErrorType
                ErrorMessage = $ErrorMessage
                Server       = $null
                IsReadOnly   = $true
            }
        }

        $script:NewTestKrbtgtProvider = {
            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestKrbtgtProviderResult `
                -Status $ObjectStatus `
                -Data $Objects `
                -ErrorType $ErrorType `
                -ErrorMessage $ErrorMessage

            $Provider = [PSCustomObject]@{
                Server       = $null
                DomainResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ DNSRoot = 'example.test' })
                }
                ForestResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ Name = 'example.test' })
                }
                ObjectResult = $ObjectResult
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetADObjects -Value {
                param($LdapFilter, $SearchBase, $Properties)
                return $this.ObjectResult
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'reports Informational when the password is fresh' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            ObjectGUID        = [guid]'55555555-5555-5555-5555-555555555555'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = (Get-Date).AddDays(-10)
        }

        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
            )
        )[0]

        $Result.CheckId | Should -Be 'AD-KRBTGT-PASSWORD-AGE'
        $Result.Category | Should -Be 'Kerberos'
        $Result.Severity | Should -Be 'Informational'
    }

    It 'reports High when the password age exceeds the threshold' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = (Get-Date).AddDays(-200)
        }

        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
            ) -MaxPasswordAgeDays 180
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'reports Critical when the password age exceeds twice the threshold' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = (Get-Date).AddDays(-800)
        }

        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
            ) -MaxPasswordAgeDays 180
        )[0]

        $Result.Severity | Should -Be 'Critical'
    }

    It 'reports Critical when PasswordLastSet is missing' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = $null
        }

        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
            )
        )[0]

        $Result.Severity | Should -Be 'Critical'
        $Result.Confidence | Should -Be 'Medium'
    }

    It 'reports Error status when the krbtgt account cannot be found' {
        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @()
            )
        )[0]

        $Result.Status | Should -Be 'Error'
    }

    It 'returns structured results for NotAvailable provider status' {
        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = (Get-Date).AddDays(-10)
        }

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
        }

        $Results = @(Get-AssessmentADKrbtgtPasswordAge -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Krbtgt = [PSCustomObject]@{
            Name              = 'krbtgt'
            DistinguishedName = 'CN=krbtgt,DC=example,DC=test'
            SamAccountName    = 'krbtgt'
            PasswordLastSet   = (Get-Date).AddDays(-10)
        }

        $Result = @(
            Get-AssessmentADKrbtgtPasswordAge -Provider (
                & $script:NewTestKrbtgtProvider -Objects @($Krbtgt)
            )
        )[0]

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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADKrbtgtPasswordAge.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
