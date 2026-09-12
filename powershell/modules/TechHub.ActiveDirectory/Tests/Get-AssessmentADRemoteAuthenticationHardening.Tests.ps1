#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteAuthenticationHardening' {

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

        function script:New-HardenedCimResult {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{
                    LmCompatibilityLevel       = 5
                    NoLmHash                   = 1
                    LdapServerIntegrity        = 2
                    LdapServerIntegrityChecked = $true
                }
                ErrorType    = $null
                ErrorMessage = $null
                Transport    = 'WSMan'
            }
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'uses the supplied ComputerName list without discovery' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            New-HardenedCimResult
        }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-AUTH-HARDENING'
        $Results[0].Category | Should -Be 'Hardening'

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'discovers domain controllers by default when ComputerName is not supplied' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            New-HardenedCimResult
        }
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith {
            @([PSCustomObject]@{ ComputerName = 'dc01' }, [PSCustomObject]@{ ComputerName = 'dc02' })
        }

        $Results = @(Get-AssessmentADRemoteAuthenticationHardening -Server 'dc01.example.test')

        $Results.Count | Should -Be 2

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $TargetType -eq 'DomainController'
        } -Times 1
    }

    It 'reports Informational when all settings are hardened' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            New-HardenedCimResult
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.Weaknesses.Count | Should -Be 0
    }

    It 'reports High when LM hash storage is not disabled' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{
                    LmCompatibilityLevel       = 5
                    NoLmHash                   = 0
                    LdapServerIntegrity        = 2
                    LdapServerIntegrityChecked = $true
                }
                Transport = 'WSMan'
            }
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'reports Medium when LmCompatibilityLevel is weak but NoLmHash is fine' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{
                    LmCompatibilityLevel       = 3
                    NoLmHash                   = 1
                    LdapServerIntegrity        = 2
                    LdapServerIntegrityChecked = $true
                }
                Transport = 'WSMan'
            }
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Medium'
    }

    It 'does not evaluate LDAPServerIntegrity when the key is absent (non-domain-controller)' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{
                    LmCompatibilityLevel       = 5
                    NoLmHash                   = 1
                    LdapServerIntegrity        = $null
                    LdapServerIntegrityChecked = $false
                }
                Transport = 'WSMan'
            }
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'srv01')[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.Weaknesses | Should -Not -Match 'LDAPServerIntegrity'
    }

    It 'returns a NotAvailable finding when the transport fails' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status       = 'NotAvailable'
                ErrorType    = 'RemoteTransportUnavailable'
                ErrorMessage = 'Synthetic failure'
            }
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'RemoteTransportUnavailable'
    }

    It 'returns nothing when no targets are supplied or discovered' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteAuthenticationHardening -Server 'dc01.example.test')

        $Results.Count | Should -Be 0
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            New-HardenedCimResult
        }

        $Result = @(Get-AssessmentADRemoteAuthenticationHardening -ComputerName 'dc01')[0]

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

    It 'contains no direct AD cmdlets, modification cmdlets, or WinRM execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADRemoteAuthenticationHardening.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
