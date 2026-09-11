#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADKerberoasting' {

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

        $script:NewTestKerberoastingProviderResult = {
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

        $script:NewTestKerberoastingProvider = {
            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestKerberoastingProviderResult `
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
        $Script:WeakPrivileged = [PSCustomObject]@{
            Name                 = 'svc-sql'
            DistinguishedName    = 'CN=svc-sql,DC=example,DC=test'
            ObjectGUID           = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass          = @('top', 'person', 'user')
            SamAccountName       = 'svc-sql'
            UserAccountControl   = 0
            Enabled              = $true
            ServicePrincipalName = @('MSSQLSvc/db01.example.test:1433')
            PasswordLastSet      = (Get-Date).AddDays(-800)
            AdminCount           = 1
        }

        $Script:StrongUnprivileged = [PSCustomObject]@{
            Name                          = 'svc-app'
            DistinguishedName             = 'CN=svc-app,DC=example,DC=test'
            ObjectGUID                    = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass                   = @('top', 'person', 'user')
            SamAccountName                = 'svc-app'
            UserAccountControl            = 0
            Enabled                       = $true
            ServicePrincipalName          = @('HTTP/app01.example.test')
            PasswordLastSet               = (Get-Date).AddDays(-10)
            AdminCount                    = 0
            'msDS-SupportedEncryptionTypes' = 24
        }
    }

    It 'detects kerberoastable accounts from synthetic provider data' {
        $Results = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($Script:WeakPrivileged, $Script:StrongUnprivileged)
            )
        )

        $Results.Count | Should -Be 2
        $Results[0].CheckId | Should -Be 'AD-KERBEROASTING'
        $Results[0].Category | Should -Be 'Kerberos'
    }

    It 'skips accounts without a service principal name' {
        $NoSpn = $Script:WeakPrivileged.PSObject.Copy()
        $NoSpn.ServicePrincipalName = @()

        $Results = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($NoSpn)
            )
        )

        $Results.Count | Should -Be 0
    }

    It 'flags a privileged account without AES support as Critical' {
        $Result = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($Script:WeakPrivileged)
            )
        )[0]

        $Result.Severity | Should -Be 'Critical'
        $Result.Evidence.IsPrivileged | Should -BeTrue
        $Result.Evidence.WeakEncryptionSupported | Should -BeTrue
    }

    It 'treats a non-privileged account with AES support as Low' {
        $Result = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($Script:StrongUnprivileged)
            )
        )[0]

        $Result.Severity | Should -Be 'Low'
        $Result.Evidence.WeakEncryptionSupported | Should -BeFalse
    }

    It 'treats missing encryption type data as weak' {
        $NoEncryptionData = $Script:StrongUnprivileged.PSObject.Copy()
        $NoEncryptionData.PSObject.Properties.Remove('msDS-SupportedEncryptionTypes')

        $Result = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($NoEncryptionData)
            )
        )[0]

        $Result.Evidence.WeakEncryptionSupported | Should -BeTrue
    }

    It 'lowers severity to Informational for disabled accounts' {
        $Disabled = $Script:WeakPrivileged.PSObject.Copy()
        $Disabled.Enabled = $false
        $Disabled.UserAccountControl = 2

        $Result = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($Disabled)
            )
        )[0]

        $Result.Severity | Should -Be 'Informational'
    }

    It 'excludes accounts matching ExcludedAccountPatterns' {
        $Results = @(
            Get-AssessmentADKerberoasting `
                -Provider (& $script:NewTestKerberoastingProvider -Objects @($Script:WeakPrivileged)) `
                -ExcludedAccountPatterns 'svc-sql'
        )

        $Results.Count | Should -Be 0
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Unavailable = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Unavailable.Status | Should -Be 'NotAvailable'
        $Unavailable.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestKerberoastingProvider -Objects @($Script:WeakPrivileged)
        }

        $Results = @(Get-AssessmentADKerberoasting -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Result = @(
            Get-AssessmentADKerberoasting -Provider (
                & $script:NewTestKerberoastingProvider -Objects @($Script:WeakPrivileged)
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADKerberoasting.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
