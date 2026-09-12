#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADPasswordNeverExpiresAccounts' {

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

        $script:NewTestPneProviderResult = {
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

        $script:NewTestPneProvider = {
            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestPneProviderResult `
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

    BeforeEach {
        $Script:RegularUser = [PSCustomObject]@{
            Name                 = 'svc-legacy'
            DistinguishedName    = 'CN=svc-legacy,DC=example,DC=test'
            ObjectGUID           = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass          = @('top', 'person', 'user')
            SamAccountName       = 'svc-legacy'
            UserAccountControl   = 65536
            Enabled              = $true
            PasswordNeverExpires = $true
            PasswordLastSet      = (Get-Date).AddDays(-900)
            AdminCount           = 0
        }

        $Script:PrivilegedUser = [PSCustomObject]@{
            Name                 = 'break-glass-admin'
            DistinguishedName    = 'CN=break-glass-admin,DC=example,DC=test'
            ObjectGUID           = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass          = @('top', 'person', 'user')
            SamAccountName       = 'break-glass-admin'
            UserAccountControl   = 65536
            Enabled              = $true
            PasswordNeverExpires = $true
            PasswordLastSet      = (Get-Date).AddDays(-30)
            AdminCount           = 1
        }

        $Script:DisabledUser = [PSCustomObject]@{
            Name                 = 'old-disabled'
            DistinguishedName    = 'CN=old-disabled,DC=example,DC=test'
            ObjectGUID           = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass          = @('top', 'person', 'user')
            SamAccountName       = 'old-disabled'
            UserAccountControl   = 65538
            Enabled              = $false
            PasswordNeverExpires = $true
            PasswordLastSet      = (Get-Date).AddDays(-900)
            AdminCount           = 0
        }
    }

    It 'detects accounts with DONT_EXPIRE_PASSWORD from synthetic provider data' {
        $Results = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (& $script:NewTestPneProvider -Objects @($Script:RegularUser))
        )

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-PASSWORD-NEVER-EXPIRES'
        $Results[0].Category | Should -Be 'AccountHygiene'
    }

    It 'treats a non-privileged account as Low' {
        $Result = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (& $script:NewTestPneProvider -Objects @($Script:RegularUser))
        )[0]

        $Result.Severity | Should -Be 'Low'
    }

    It 'treats a privileged account as High' {
        $Result = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (& $script:NewTestPneProvider -Objects @($Script:PrivilegedUser))
        )[0]

        $Result.Severity | Should -Be 'High'
        $Result.Evidence.IsPrivileged | Should -BeTrue
    }

    It 'lowers severity to Informational for disabled accounts' {
        $Result = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (& $script:NewTestPneProvider -Objects @($Script:DisabledUser))
        )[0]

        $Result.Severity | Should -Be 'Informational'
    }

    It 'excludes accounts matching ExcludedAccountPatterns' {
        $Results = @(
            Get-AssessmentADPasswordNeverExpiresAccounts `
                -Provider (& $script:NewTestPneProvider -Objects @($Script:RegularUser)) `
                -ExcludedAccountPatterns 'svc-legacy'
        )

        $Results.Count | Should -Be 0
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Unavailable = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (
                & $script:NewTestPneProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Unavailable.Status | Should -Be 'NotAvailable'
        $Unavailable.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestPneProvider -Objects @($Script:RegularUser)
        }

        $Results = @(Get-AssessmentADPasswordNeverExpiresAccounts -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Result = @(
            Get-AssessmentADPasswordNeverExpiresAccounts -Provider (& $script:NewTestPneProvider -Objects @($Script:RegularUser))
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADPasswordNeverExpiresAccounts.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
