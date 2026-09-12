#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADStaleAccounts' {

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

        $script:NewTestStaleProviderResult = {
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

        $script:NewTestStaleProvider = {
            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestStaleProviderResult `
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
        $Script:FreshUser = [PSCustomObject]@{
            Name               = 'active-user'
            DistinguishedName  = 'CN=active-user,DC=example,DC=test'
            ObjectGUID         = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'active-user'
            UserAccountControl = 512
            Enabled            = $true
            LastLogonTimestamp = (Get-Date).AddDays(-5)
            AdminCount         = 0
        }

        $Script:StaleUser = [PSCustomObject]@{
            Name               = 'stale-user'
            DistinguishedName  = 'CN=stale-user,DC=example,DC=test'
            ObjectGUID         = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'stale-user'
            UserAccountControl = 512
            Enabled            = $true
            LastLogonTimestamp = (Get-Date).AddDays(-200)
            AdminCount         = 0
        }

        $Script:StalePrivilegedUser = [PSCustomObject]@{
            Name               = 'stale-admin'
            DistinguishedName  = 'CN=stale-admin,DC=example,DC=test'
            ObjectGUID         = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'stale-admin'
            UserAccountControl = 512
            Enabled            = $true
            LastLogonTimestamp = (Get-Date).AddDays(-200)
            AdminCount         = 1
        }

        $Script:DisabledStaleUser = [PSCustomObject]@{
            Name               = 'disabled-user'
            DistinguishedName  = 'CN=disabled-user,DC=example,DC=test'
            ObjectGUID         = [guid]'44444444-4444-4444-4444-444444444444'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'disabled-user'
            UserAccountControl = 514
            Enabled            = $false
            LastLogonTimestamp = (Get-Date).AddDays(-500)
            AdminCount         = 0
        }

        $Script:NeverLoggedOnUser = [PSCustomObject]@{
            Name               = 'never-logged-on'
            DistinguishedName  = 'CN=never-logged-on,DC=example,DC=test'
            ObjectGUID         = [guid]'55555555-5555-5555-5555-555555555555'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'never-logged-on'
            UserAccountControl = 512
            Enabled            = $true
            LastLogonTimestamp = $null
            AdminCount         = 0
        }
    }

    It 'skips accounts logged on within the threshold' {
        $Results = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:FreshUser))
        )

        $Results.Count | Should -Be 0
    }

    It 'flags a stale non-privileged account as Medium' {
        $Result = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:StaleUser))
        )[0]

        $Result.CheckId | Should -Be 'AD-STALE-ACCOUNTS'
        $Result.Category | Should -Be 'AccountHygiene'
        $Result.Severity | Should -Be 'Medium'
        $Result.Evidence.LastLogonAgeDays | Should -BeGreaterThan 90
    }

    It 'flags a stale privileged account as High' {
        $Result = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:StalePrivilegedUser))
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'skips disabled accounts regardless of last logon age' {
        $Results = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:DisabledStaleUser))
        )

        $Results.Count | Should -Be 0
    }

    It 'reports accounts with no recorded logon separately, at Low confidence' {
        $Result = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:NeverLoggedOnUser))
        )[0]

        $Result.Confidence | Should -Be 'Low'
        $Result.Evidence.LastLogonTimestamp | Should -BeNullOrEmpty
    }

    It 'respects a custom StaleDays threshold' {
        $Results = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:FreshUser)) -StaleDays 1
        )

        $Results.Count | Should -Be 1
    }

    It 'excludes accounts matching ExcludedAccountPatterns' {
        $Results = @(
            Get-AssessmentADStaleAccounts `
                -Provider (& $script:NewTestStaleProvider -Objects @($Script:StaleUser)) `
                -ExcludedAccountPatterns 'stale-user'
        )

        $Results.Count | Should -Be 0
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Unavailable = @(
            Get-AssessmentADStaleAccounts -Provider (
                & $script:NewTestStaleProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Unavailable.Status | Should -Be 'NotAvailable'
        $Unavailable.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestStaleProvider -Objects @($Script:StaleUser)
        }

        $Results = @(Get-AssessmentADStaleAccounts -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Result = @(
            Get-AssessmentADStaleAccounts -Provider (& $script:NewTestStaleProvider -Objects @($Script:StaleUser))
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADStaleAccounts.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
