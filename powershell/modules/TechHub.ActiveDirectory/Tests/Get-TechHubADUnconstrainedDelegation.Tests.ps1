#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-TechHubADConstrainedDelegation provider migration' {

    BeforeAll {

        # ============================================================
        # TEST PATH / MODULE BOOTSTRAP
        # ============================================================

        $script:TestFile = $PSCommandPath

        if ([string]::IsNullOrWhiteSpace($script:TestFile)) {
            throw 'Unable to determine test file path.'
        }

        $script:TestsRoot = Split-Path -Parent $script:TestFile
        $script:ModuleRoot = Split-Path -Parent $script:TestsRoot

        $script:ModulePath = Join-Path `
            -Path $script:ModuleRoot `
            -ChildPath 'TechHub.ActiveDirectory.psm1'

        if (-not (Test-Path -LiteralPath $script:ModulePath)) {
            throw "Module not found: $script:ModulePath"
        }

        Import-Module `
            -Name $script:ModulePath `
            -Force `
            -ErrorAction Stop


        # ============================================================
        # SYNTHETIC PROVIDER RESULT FACTORY
        # ============================================================

        $script:NewTestConstrainedProviderResult = {

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


        # ============================================================
        # SYNTHETIC PROVIDER FACTORY
        # ============================================================

        $script:NewTestConstrainedProvider = {

            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestConstrainedProviderResult `
                -Status $ObjectStatus `
                -Data $Objects `
                -ErrorType $ErrorType `
                -ErrorMessage $ErrorMessage

            $Provider = [PSCustomObject]@{
                Server = $null

                DomainResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data = @(
                        [PSCustomObject]@{
                            DNSRoot = 'example.test'
                        }
                    )
                }

                ForestResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data = @(
                        [PSCustomObject]@{
                            Name = 'example.test'
                        }
                    )
                }

                ObjectResult = $ObjectResult

                LastLdapFilter = $null
                LastSearchBase = $null
                LastProperties = $null
            }

            Add-Member `
                -InputObject $Provider `
                -MemberType ScriptMethod `
                -Name GetDomainInformation `
                -Value {
                    return $this.DomainResult
                }

            Add-Member `
                -InputObject $Provider `
                -MemberType ScriptMethod `
                -Name GetForestInformation `
                -Value {
                    return $this.ForestResult
                }

            Add-Member `
                -InputObject $Provider `
                -MemberType ScriptMethod `
                -Name GetADObjects `
                -Value {
                    param(
                        $LdapFilter,
                        $SearchBase,
                        $Properties
                    )

                    $this.LastLdapFilter = $LdapFilter
                    $this.LastSearchBase = $SearchBase
                    $this.LastProperties = $Properties

                    return $this.ObjectResult
                }

            return $Provider
        }
    }


    AfterAll {

        Remove-Module `
            -Name TechHub.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue
    }


    BeforeEach {

        $Script:User = [PSCustomObject]@{
            Name                       = 'svc-web'
            DistinguishedName          = 'CN=svc-web,DC=example,DC=test'
            ObjectGUID                 = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass                = @(
                'top'
                'person'
                'user'
            )
            ObjectCategory             = 'person'
            SamAccountName             = 'svc-web'
            UserAccountControl         = 0
            Enabled                    = $true
            ServicePrincipalName       = @(
                'HTTP/web.example.test'
            )
            'msDS-AllowedToDelegateTo' = @(
                'HTTP/api.example.test'
            )
        }


        $Script:Computer = [PSCustomObject]@{
            Name                       = 'WEB01'
            DistinguishedName          = 'CN=WEB01,DC=example,DC=test'
            ObjectGUID                 = [guid]'44444444-4444-4444-4444-444444444444'
            ObjectClass                = @(
                'top'
                'person'
                'computer'
            )
            ObjectCategory             = 'computer'
            SamAccountName             = 'WEB01$'
            UserAccountControl         = 0
            Enabled                    = $true
            ServicePrincipalName       = @(
                'HOST/WEB01.example.test'
            )
            'msDS-AllowedToDelegateTo' = @(
                'HTTP/api.example.test'
            )
        }


        $Script:Provider = & $script:NewTestConstrainedProvider `
            -Objects @(
                $Script:User
                $Script:Computer
            )
    }


    It 'detects constrained delegation from synthetic provider data' {

        $Results = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider
        )

        $Results.Count |
            Should -Be 2

        $Results[0].CheckId |
            Should -Be 'AD-CONSTRAINED-DELEGATION'

        $Results[0].Evidence.AllowedToDelegateTo |
            Should -Contain 'HTTP/api.example.test'
    }


    It 'distinguishes user and computer accounts' {

        $Results = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider
        )

        ($Results |
            Where-Object ObjectType -eq 'User').Count |
            Should -Be 1

        ($Results |
            Where-Object ObjectType -eq 'Computer').Count |
            Should -Be 1
    }


    It 'handles one and multiple delegation targets' {

        $Script:User.'msDS-AllowedToDelegateTo' = @(
            'HTTP/api.example.test'
            'LDAP/dc.example.test'
        )

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -Objects @($Script:User)
                )
        )[0]

        $Result.Evidence.AllowedToDelegateTo.Count |
            Should -Be 2

        $Result.Severity |
            Should -Be 'Medium'
    }


    It 'skips objects with missing delegation targets' {

        $NoTarget = [PSCustomObject]@{
            Name                       = 'NO-TARGET'
            UserAccountControl         = 0
            ObjectClass                = @('user')
            'msDS-AllowedToDelegateTo' = $null
        }

        $Results = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -Objects @($NoTarget)
                )
        )

        $Results.Count |
            Should -Be 0
    }


    It 'handles empty provider results' {

        $Results = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider
                )
        )

        $Results.Count |
            Should -Be 0
    }


    It 'preserves Available and Partial provider status' {

        $Available = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider
        )[0]

        $Available.Evidence.ProviderStatus |
            Should -Be 'Available'


        $Partial = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -ObjectStatus 'Partial' `
                        -Objects @($Script:User)
                )
        )[0]

        $Partial.Evidence.ProviderStatus |
            Should -Be 'Partial'
    }


    It 'returns structured results for NotAvailable and Error provider status' {

        $Unavailable = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -ObjectStatus 'NotAvailable' `
                        -ErrorType 'ModuleUnavailable' `
                        -ErrorMessage 'Synthetic unavailable'
                )
        )[0]

        $Unavailable.Status |
            Should -Be 'NotAvailable'

        $Unavailable.Evidence.ErrorType |
            Should -Be 'ModuleUnavailable'


        $ErrorResult = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -ObjectStatus 'Error' `
                        -ErrorType 'LdapError' `
                        -ErrorMessage 'Synthetic LDAP failure'
                )
        )[0]

        $ErrorResult.Status |
            Should -Be 'Error'

        $ErrorResult.Evidence.ErrorType |
            Should -Be 'LdapError'
    }


    It 'handles incomplete objects and missing SPNs' {

        $Incomplete = [PSCustomObject]@{
            Name                       = 'INCOMPLETE'
            ObjectClass                = @('user')
            UserAccountControl         = 0
            'msDS-AllowedToDelegateTo' = 'HTTP/api.example.test'
        }

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -Objects @($Incomplete)
                )
        )[0]

        $Result.Confidence |
            Should -Be 'Medium'

        $Result.Evidence.ServicePrincipalNames.Count |
            Should -Be 0
    }


    It 'handles enabled and disabled accounts' {

        $Disabled = $Script:User.PSObject.Copy()

        $Disabled.Enabled = $false
        $Disabled.UserAccountControl = 2

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider (
                    & $script:NewTestConstrainedProvider `
                        -Objects @($Disabled)
                )
        )[0]

        $Result.Evidence.AccountEnabled |
            Should -BeFalse

        $Result.Severity |
            Should -Be 'Informational'
    }


    It 'supports configured severity patterns' {

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider `
                -CriticalServicePatterns 'HTTP/*'
        )[0]

        $Result.Severity |
            Should -Be 'High'


        $Excluded = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider `
                -ExcludedServicePatterns 'HTTP/*'
        )[0]

        $Excluded.Status |
            Should -Be 'NotApplicable'
    }


    It 'passes Server and SearchBase to the provider' {

        $Provider = & $script:NewTestConstrainedProvider `
            -Objects @($Script:User)

        Get-TechHubADConstrainedDelegation `
            -Provider $Provider `
            -Server 'dc01.example.test' `
            -SearchBase 'OU=Service Accounts,DC=example,DC=test' |
            Out-Null

        $Provider.LastSearchBase |
            Should -Be 'OU=Service Accounts,DC=example,DC=test'

        $Provider.Server |
            Should -BeNullOrEmpty

        $Provider.LastProperties |
            Should -Contain 'msDS-AllowedToDelegateTo'
    }


    It 'creates a provider when invoked without one' {

        Mock New-TechHubADProvider `
            -ModuleName TechHub.ActiveDirectory `
            -MockWith {
                & $script:NewTestConstrainedProvider `
                    -Objects @($Script:User)
            }

        $Results = @(
            Get-TechHubADConstrainedDelegation `
                -Server 'dc01.example.test'
        )

        $Results.Count |
            Should -Be 1

        Assert-MockCalled `
            New-TechHubADProvider `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test'
            } `
            -Times 1
    }


    It 'returns the complete Finding Contract v1 and remains read-only' {

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider
        )[0]

        @(
            'AssessmentId'
            'CheckId'
            'CheckName'
            'FindingId'
            'Title'
            'Description'
            'Category'
            'Severity'
            'Confidence'
            'Status'
            'AffectedObject'
            'ObjectType'
            'DistinguishedName'
            'SamAccountName'
            'ObjectGuid'
            'Evidence'
            'Risk'
            'Recommendation'
            'References'
            'CollectedAt'
            'Domain'
            'Forest'
            'DomainController'
            'IsReadOnly'
        ) |
            ForEach-Object {
                $Result.PSObject.Properties.Name |
                    Should -Contain $_
            }

        $Result.CheckName |
            Should -Be 'Constrained Delegation'

        $Result.Category |
            Should -Be 'Delegation'

        $Result.IsReadOnly |
            Should -BeTrue
    }


    It 'works solely with synthetic provider data without AD cmdlets' {

        $Result = @(
            Get-TechHubADConstrainedDelegation `
                -Provider $Script:Provider
        )[0]

        $Result.Evidence.AllowedToDelegateTo |
            Should -Contain 'HTTP/api.example.test'

        $SourcePath = Join-Path `
            -Path $script:ModuleRoot `
            -ChildPath 'Public\Get-TechHubADConstrainedDelegation.ps1'

        $Source = Get-Content `
            -LiteralPath $SourcePath `
            -Raw

        $Source -match '\bGet-AD[A-Za-z]+' |
            Should -BeFalse
    }


    It 'contains no direct AD cmdlets, modification cmdlets, or dynamic execution' {

        $SourcePath = Join-Path `
            -Path $script:ModuleRoot `
            -ChildPath 'Public\Get-TechHubADConstrainedDelegation.ps1'

        $Source = Get-Content `
            -LiteralPath $SourcePath `
            -Raw

        $Source -match '\bGet-AD[A-Za-z]+' |
            Should -BeFalse

        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' |
            Should -BeFalse

        $DynamicMarkers = @(
            'Invoke-' + 'Expression'
            'Script' + 'Block'
            'Start-' + 'Process'
            'Invoke-' + 'Command'
        )

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) |
                Should -BeFalse
        }
    }
}