#requires -Version 5.1

Set-StrictMode -Version Latest

$TestRoot = Split-Path -Parent $PSScriptRoot
$ModuleRoot = Split-Path -Parent $TestRoot
$ModuleManifest = Join-Path $ModuleRoot 'TechHub.ActiveDirectory.psd1'
$HelperPath = Join-Path $PSScriptRoot 'TechHubADContractTestHelpers.ps1'

. $HelperPath

Describe 'TechHub.ActiveDirectory finding contract v1' {

    BeforeAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue

        Import-Module $ModuleManifest -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:Domain = [PSCustomObject]@{
            DNSRoot = 'example.test'
        }

        $Script:Forest = [PSCustomObject]@{
            Name = 'example.test'
        }
    }

    Context 'Get-TechHubADUnconstrainedDelegation' {

        BeforeEach {
            $Object = [PSCustomObject]@{
                Name                  = 'APP01'
                DistinguishedName     = 'CN=APP01,DC=example,DC=test'
                ObjectGUID            = [guid]'11111111-1111-1111-1111-111111111111'
                ObjectClass           = @('top', 'person', 'computer')
                ObjectCategory        = 'computer'
                SamAccountName        = 'APP01$'
                UserAccountControl    = 0x80000
                ServicePrincipalName  = @('HOST/APP01.example.test')
                Enabled               = $true
            }

            Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory {
                $Script:Domain
            }

            Mock Get-ADForest -ModuleName TechHub.ActiveDirectory {
                $Script:Forest
            }

            Mock Get-ADObject -ModuleName TechHub.ActiveDirectory {
                @($Object)
            }
        }

        It 'returns output conforming to contract v1' {
            $Results = @(Get-TechHubADUnconstrainedDelegation)

            $Results.Count | Should -Be 1

            Assert-TechHubADFindingContract `
                -Result $Results[0] `
                -ExpectedCheckId 'AD-UNCONSTRAINED-DELEGATION' `
                -ExpectedCheckName 'Unconstrained Delegation' `
                -ExpectedCategory 'Delegation'

            Assert-TechHubADSafeOutput -Results $Results
        }

        It 'keeps CheckId stable across executions' {
            $First = @(Get-TechHubADUnconstrainedDelegation)[0]
            $Second = @(Get-TechHubADUnconstrainedDelegation)[0]

            $First.CheckId | Should -Be $Second.CheckId
        }
    }

    Context 'Get-TechHubADConstrainedDelegation' {

        BeforeEach {
            $Object = [PSCustomObject]@{
                Name                    = 'svc-web'
                DistinguishedName       = 'CN=svc-web,DC=example,DC=test'
                ObjectGUID              = [guid]'22222222-2222-2222-2222-222222222222'
                ObjectClass             = @('top', 'person', 'user')
                ObjectCategory          = 'person'
                SamAccountName          = 'svc-web'
                UserAccountControl      = 0
                Enabled                 = $true
                ServicePrincipalName    = @('HTTP/web.example.test')
                'msDS-AllowedToDelegateTo' = @('HTTP/api.example.test')
            }

            Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory {
                $Script:Domain
            }

            Mock Get-ADForest -ModuleName TechHub.ActiveDirectory {
                $Script:Forest
            }

            Mock Get-ADObject -ModuleName TechHub.ActiveDirectory {
                @($Object)
            }
        }

        It 'returns output conforming to contract v1' {
            $Results = @(Get-TechHubADConstrainedDelegation)

            $Results.Count | Should -Be 1

            Assert-TechHubADFindingContract `
                -Result $Results[0] `
                -ExpectedCheckId 'AD-CONSTRAINED-DELEGATION' `
                -ExpectedCheckName 'Constrained Delegation' `
                -ExpectedCategory 'Delegation'

            Assert-TechHubADSafeOutput -Results $Results
        }

        It 'keeps CheckId stable across executions' {
            $First = @(Get-TechHubADConstrainedDelegation)[0]
            $Second = @(Get-TechHubADConstrainedDelegation)[0]

            $First.CheckId | Should -Be $Second.CheckId
        }
    }

    Context 'Get-TechHubADRBCD' {

        BeforeEach {
            $TrusteeSid = 'S-1-5-21-100-200-300-1101'

            $Descriptor = New-TechHubADContractDescriptor `
                -IdentityReference $TrusteeSid

            $Target = [PSCustomObject]@{
                Name = 'APP01'
                DistinguishedName = 'CN=APP01,DC=example,DC=test'
                ObjectGUID = [guid]'33333333-3333-3333-3333-333333333333'
                ObjectClass = @('top', 'person', 'computer')
                ObjectCategory = 'computer'
                SamAccountName = 'APP01$'
                UserAccountControl = 0
                Enabled = $true
                'msDS-AllowedToActOnBehalfOfOtherIdentity' = $Descriptor
            }

            $ResolvedTrustee = [PSCustomObject]@{
                Name = 'DELEGATOR01'
                DistinguishedName = 'CN=DELEGATOR01,DC=example,DC=test'
                ObjectGUID = [guid]'44444444-4444-4444-4444-444444444444'
                ObjectClass = @('top', 'person', 'computer')
                SamAccountName = 'DELEGATOR01$'
                Enabled = $true
                UserAccountControl = 0
            }

            Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory {
                $Script:Domain
            }

            Mock Get-ADForest -ModuleName TechHub.ActiveDirectory {
                $Script:Forest
            }

            Mock Get-ADObject -ModuleName TechHub.ActiveDirectory {
                if ($PSBoundParameters.ContainsKey('Identity')) {
                    $ResolvedTrustee
                }
                else {
                    @($Target)
                }
            }
        }

        It 'returns output conforming to contract v1' {
            $Results = @(Get-TechHubADRBCD)

            $Results.Count | Should -Be 1

            Assert-TechHubADFindingContract `
                -Result $Results[0] `
                -ExpectedCheckId 'AD-RBCD' `
                -ExpectedCheckName 'Resource-Based Constrained Delegation' `
                -ExpectedCategory 'Delegation'

            Assert-TechHubADSafeOutput -Results $Results
        }

        It 'keeps CheckId stable across executions' {
            $First = @(Get-TechHubADRBCD)[0]
            $Second = @(Get-TechHubADRBCD)[0]

            $First.CheckId | Should -Be $Second.CheckId
        }
    }

    Context 'Get-TechHubADPrivilegedGroup' {

        BeforeEach {
            $Group = [PSCustomObject]@{
                Name = 'Domain Admins'
                SamAccountName = 'Domain Admins'
                DistinguishedName = 'CN=Domain Admins,CN=Users,DC=example,DC=test'
                ObjectGUID = [guid]'55555555-5555-5555-5555-555555555555'
                ObjectClass = @('top', 'group')
            }

            $Member = [PSCustomObject]@{
                Name = 'alice'
                SamAccountName = 'alice'
                DistinguishedName = 'CN=alice,CN=Users,DC=example,DC=test'
                ObjectGUID = [guid]'66666666-6666-6666-6666-666666666666'
                ObjectClass = @('top', 'person', 'user')
                SID = 'S-1-5-21-100-200-300-1101'
            }

            $Detail = [PSCustomObject]@{
                Name = 'alice'
                SamAccountName = 'alice'
                DistinguishedName = $Member.DistinguishedName
                ObjectGUID = $Member.ObjectGUID
                ObjectClass = @('user')
                SID = $Member.SID
                Enabled = $true
                adminCount = 0
                PasswordNeverExpires = $false
            }

            Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory {
                $Script:Domain
            }

            Mock Get-ADForest -ModuleName TechHub.ActiveDirectory {
                $Script:Forest
            }

            Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory {
                @($Group)
            }

            Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory {
                @($Member)
            }

            Mock Get-ADObject -ModuleName TechHub.ActiveDirectory {
                $Detail
            }
        }

        It 'returns output conforming to contract v1' {
            $Results = @(Get-TechHubADPrivilegedGroup -IncludeDisabled)

            $Results.Count | Should -Be 1

            Assert-TechHubADFindingContract `
                -Result $Results[0] `
                -ExpectedCheckId 'AD-PRIVILEGED-GROUP' `
                -ExpectedCheckName 'Privileged Groups' `
                -ExpectedCategory 'PrivilegedAccess'

            Assert-TechHubADSafeOutput -Results $Results
        }

        It 'keeps CheckId stable across executions' {
            $First = @(Get-TechHubADPrivilegedGroup -IncludeDisabled)[0]
            $Second = @(Get-TechHubADPrivilegedGroup -IncludeDisabled)[0]

            $First.CheckId | Should -Be $Second.CheckId
        }
    }
}