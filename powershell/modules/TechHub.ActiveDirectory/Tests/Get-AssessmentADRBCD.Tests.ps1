#requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'ConvertFrom-TechHubADRBCDDescriptor' {

    BeforeAll {

        $TestModulePath = Join-Path `
            -Path $PSScriptRoot `
            -ChildPath '..'

        Import-Module `
            -Name $TestModulePath `
            -Force `
            -ErrorAction Stop
    }

    AfterAll {

        Remove-Module `
            -Name TechHub.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue
    }

    It 'normalizes a synthetic security descriptor' {

        $Rule = [PSCustomObject]@{
            IdentityReference = 'S-1-5-21-100-200-300-1101'
            AccessControlType = 'Allow'
            AccessMask        = 983551
            ObjectType        = [guid]::Empty
        }

        $Descriptor = [PSCustomObject]@{
            AccessRules = @($Rule)
        }

        Add-Member `
            -InputObject $Descriptor `
            -MemberType ScriptMethod `
            -Name GetAccessRules `
            -Value {
                param(
                    [bool]$IncludeExplicit,
                    [bool]$IncludeInherited,
                    [object]$TargetType
                )

                return $this.AccessRules
            }

        $Result = @(
            InModuleScope TechHub.ActiveDirectory {

                param($TestDescriptor)

                ConvertFrom-TechHubADRBCDDescriptor `
                    -Descriptor $TestDescriptor

            } -Parameters @{
                TestDescriptor = $Descriptor
            }
        )

        $Result.Count |
            Should -Be 1

        $Result[0].SID |
            Should -Be 'S-1-5-21-100-200-300-1101'

        $Result[0].AccessType |
            Should -Be 'Allow'

        $Result[0].AccessMask |
            Should -Be 983551

        $Result[0].ObjectType |
            Should -Be ([guid]::Empty)
    }
}


Describe 'Get-AssessmentADRBCD' {

    BeforeAll {

        $TestModulePath = Join-Path `
            -Path $PSScriptRoot `
            -ChildPath '..'

        Import-Module `
            -Name $TestModulePath `
            -Force `
            -ErrorAction Stop
    }

    AfterAll {

        Remove-Module `
            -Name TechHub.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue
    }

    BeforeEach {

        $Script:TargetSid =
            'S-1-5-21-100-200-300-1101'

        $Script:SecondSid =
            'S-1-5-21-100-200-300-1102'

        $Script:UserSid =
            'S-1-5-21-100-200-300-1201'

        $Script:GroupSid =
            'S-1-5-21-100-200-300-1202'

        $Script:Target = [PSCustomObject]@{
            Name = 'APP01'

            DistinguishedName =
                'CN=APP01,OU=Servers,DC=example,DC=test'

            ObjectGUID =
                [guid]'55555555-5555-5555-5555-555555555555'

            ObjectClass = @(
                'top'
                'person'
                'computer'
            )

            ObjectCategory = 'computer'

            SamAccountName = 'APP01$'

            UserAccountControl = 0

            Enabled = $true
        }

        $Script:Computer = [PSCustomObject]@{
            Name = 'DELEGATOR01'

            ObjectClass = @(
                'top'
                'person'
                'computer'
            )

            ObjectCategory = 'computer'

            SamAccountName = 'DELEGATOR01$'

            DistinguishedName =
                'CN=DELEGATOR01,OU=Servers,DC=example,DC=test'

            ObjectGUID =
                [guid]'66666666-6666-6666-6666-666666666666'

            Enabled = $true

            UserAccountControl = 0
        }

        $Script:User = [PSCustomObject]@{
            Name = 'svc-app'

            ObjectClass = @(
                'top'
                'person'
                'user'
            )

            ObjectCategory = 'person'

            SamAccountName = 'svc-app'

            DistinguishedName =
                'CN=svc-app,CN=Users,DC=example,DC=test'

            ObjectGUID =
                [guid]'77777777-7777-7777-7777-777777777777'

            Enabled = $false

            UserAccountControl = 0
        }

        $Script:Group = [PSCustomObject]@{
            Name = 'App-Delegation'

            ObjectClass = @(
                'top'
                'group'
            )

            ObjectCategory = 'group'

            SamAccountName = 'App-Delegation'

            DistinguishedName =
                'CN=App-Delegation,CN=Users,DC=example,DC=test'

            ObjectGUID =
                [guid]'88888888-8888-8888-8888-888888888888'

            Enabled = $true

            UserAccountControl = 0
        }

        $Script:Descriptor = [PSCustomObject]@{
            AccessRules = @(
                [PSCustomObject]@{
                    IdentityReference = $Script:TargetSid
                    AccessControlType = 'Allow'
                    AccessMask        = 983551
                    ObjectType        = [guid]::Empty
                }
            )
        }

        Add-Member `
            -InputObject $Script:Descriptor `
            -MemberType ScriptMethod `
            -Name GetAccessRules `
            -Value {
                param(
                    [bool]$IncludeExplicit,
                    [bool]$IncludeInherited,
                    [object]$TargetType
                )

                return $this.AccessRules
            }

        $Script:Target |
            Add-Member `
                -MemberType NoteProperty `
                -Name 'msDS-AllowedToActOnBehalfOfOtherIdentity' `
                -Value $Script:Descriptor `
                -Force

        $Script:CapturedServer = $null
        $Script:CapturedSearchBase = $null
        $Script:CapturedLDAPFilter = $null

        Mock Get-ADDomain `
            -ModuleName TechHub.ActiveDirectory {

            [PSCustomObject]@{
                DNSRoot = 'example.test'
            }
        }

        Mock Get-ADForest `
            -ModuleName TechHub.ActiveDirectory {

            [PSCustomObject]@{
                Name = 'example.test'
            }
        }

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter,
                [object[]]$Properties,
                [string]$SearchBase,
                [string]$Server,
                [string]$ErrorAction
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                $Script:CapturedServer = $Server
                $Script:CapturedSearchBase = $SearchBase
                $Script:CapturedLDAPFilter = $LDAPFilter

                return @(
                    $Script:Target
                )
            }

            switch ($Identity) {

                $Script:TargetSid {
                    return $Script:Computer
                }

                $Script:SecondSid {
                    return $Script:Computer
                }

                $Script:UserSid {
                    return $Script:User
                }

                $Script:GroupSid {
                    return $Script:Group
                }

                default {
                    throw "Unexpected trustee identity: $Identity"
                }
            }
        }
    }


    It 'returns no finding when the attribute is absent' {

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                return @(
                    [PSCustomObject]@{
                        Name = 'EMPTY'

                        ObjectClass = @(
                            'top'
                            'person'
                            'computer'
                        )

                        ObjectGUID =
                            [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

                        DistinguishedName =
                            'CN=EMPTY,OU=Servers,DC=example,DC=test'

                        SamAccountName = 'EMPTY$'

                        Enabled = $true
                    }
                )
            }

            return $Script:Computer
        }

        @(Get-AssessmentADRBCD).Count |
            Should -Be 0
    }


    It 'handles a valid descriptor and one resolvable computer trustee' {

        $Result = @(Get-AssessmentADRBCD)[0]

        $Result.Evidence.SecurityDescriptorPresent |
            Should -BeTrue

        $Result.Evidence.AllowedIdentities.Count |
            Should -Be 1

        $Result.Evidence.ResolvedIdentities.Count |
            Should -Be 1

        $Result.Evidence.ResolvedIdentities[0].ObjectType |
            Should -Be 'Computer'

        $Result.Evidence.UnresolvedSids.Count |
            Should -Be 0
    }


    It 'handles multiple trustees' {

        $Script:Descriptor.AccessRules = @(
            [PSCustomObject]@{
                IdentityReference = $Script:TargetSid
                AccessControlType = 'Allow'
                AccessMask        = 983551
                ObjectType        = [guid]::Empty
            }

            [PSCustomObject]@{
                IdentityReference = $Script:SecondSid
                AccessControlType = 'Allow'
                AccessMask        = 983551
                ObjectType        = [guid]::Empty
            }
        )

        $Result = @(Get-AssessmentADRBCD)[0]

        $Result.Evidence.AllowedIdentities.Count |
            Should -Be 2

        $Result.Evidence.ResolvedIdentities.Count |
            Should -Be 2

        $Result.Severity |
            Should -Be 'Medium'
    }


    It 'records an unresolved SID without treating it as a collection error' {

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                return @(
                    $Script:Target
                )
            }

            throw [System.Exception]::new(
                'SID not found'
            )
        }

        $Result = @(Get-AssessmentADRBCD)[0]

        $Result.Status |
            Should -Be 'Finding'

        @(
            $Result.Evidence.UnresolvedSids
        ) |
            Should -Contain $Script:TargetSid

        $Result.Confidence |
            Should -Be 'Medium'
    }


    It 'identifies a user and group trustee' {

        $Script:Descriptor.AccessRules = @(
            [PSCustomObject]@{
                IdentityReference = $Script:UserSid
                AccessControlType = 'Allow'
                AccessMask        = 1
                ObjectType        = [guid]::Empty
            }

            [PSCustomObject]@{
                IdentityReference = $Script:GroupSid
                AccessControlType = 'Allow'
                AccessMask        = 1
                ObjectType        = [guid]::Empty
            }
        )

        $Result = @(Get-AssessmentADRBCD)[0]

        @(
            $Result.Evidence.ResolvedIdentities.ObjectType
        ) |
            Should -Contain 'User'

        @(
            $Result.Evidence.ResolvedIdentities.ObjectType
        ) |
            Should -Contain 'Group'
    }


    It 'classifies a sensitive target with an unresolved trustee as critical' {

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                return @(
                    $Script:Target
                )
            }

            throw [System.Exception]::new(
                'SID not found'
            )
        }

        $Result = @(
            Get-AssessmentADRBCD `
                -SensitiveTargetPatterns 'APP*'
        )[0]

        $Result.Severity |
            Should -Be 'Critical'
    }


    It 'classifies an approved identity as a documented low-risk configuration' {

        $Result = @(
            Get-AssessmentADRBCD `
                -ApprovedIdentityPatterns $Script:TargetSid
        )[0]

        $Result.Severity |
            Should -Be 'Low'
    }


    It 'classifies an excluded identity as informational and not applicable' {

        $Result = @(
            Get-AssessmentADRBCD `
                -ExcludedIdentityPatterns $Script:TargetSid
        )[0]

        $Result.Severity |
            Should -Be 'Informational'

        $Result.Status |
            Should -Be 'NotApplicable'
    }


    It 'reports a descriptor that cannot be read' {

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                return @(
                    [PSCustomObject]@{
                        Name = 'BROKEN'

                        ObjectClass = @(
                            'top'
                            'person'
                            'computer'
                        )

                        ObjectGUID =
                            [guid]'99999999-9999-9999-9999-999999999999'

                        DistinguishedName =
                            'CN=BROKEN,OU=Servers,DC=example,DC=test'

                        SamAccountName = 'BROKEN$'

                        Enabled = $true

                        'msDS-AllowedToActOnBehalfOfOtherIdentity' =
                            [PSCustomObject]@{}
                    }
                )
            }

            throw 'Unexpected trustee lookup'
        }

        $Result = @(Get-AssessmentADRBCD)[0]

        $Result.Status |
            Should -Be 'Error'

        $Result.Evidence.SecurityDescriptorPresent |
            Should -BeFalse
    }


    It 'handles empty results and LDAP errors' {

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                return @()
            }

            throw 'LDAP failure'
        }

        @(Get-AssessmentADRBCD).Count |
            Should -Be 0
    }


    It 'returns the complete finding contract and read-only marker' {

        $Result = @(Get-AssessmentADRBCD)[0]

        $RequiredProperties = @(
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
        )

        foreach ($Property in $RequiredProperties) {

            $Result.PSObject.Properties.Name |
                Should -Contain $Property
        }

        $Result.CheckId |
            Should -Be 'AD-RBCD'

        $Result.IsReadOnly |
            Should -BeTrue
    }


    It 'supports verbose output and passes server and search base' {

        $TestServer =
            'dc01.example.test'

        $TestSearchBase =
            'OU=Servers,DC=example,DC=test'

        $Script:CapturedServer = $null
        $Script:CapturedSearchBase = $null
        $Script:CapturedLDAPFilter = $null

        Mock Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

            param(
                [string]$Identity,
                [string]$LDAPFilter,
                [object[]]$Properties,
                [string]$SearchBase,
                [string]$Server,
                [string]$ErrorAction
            )

            if (
                -not [string]::IsNullOrWhiteSpace($LDAPFilter)
            ) {

                $Script:CapturedServer = $Server
                $Script:CapturedSearchBase = $SearchBase
                $Script:CapturedLDAPFilter = $LDAPFilter

                return @(
                    $Script:Target
                )
            }

            return $Script:Computer
        }

        {
            Get-AssessmentADRBCD `
                -Server $TestServer `
                -SearchBase $TestSearchBase `
                -Verbose |
                Out-Null
        } |
            Should -Not -Throw

        $Script:CapturedServer |
            Should -Be $TestServer

        $Script:CapturedSearchBase |
            Should -Be $TestSearchBase

        $Script:CapturedLDAPFilter |
            Should -Match 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    }


    It 'contains no Active Directory modification cmdlets' {

        $SourcePath = Join-Path `
            -Path $PSScriptRoot `
            -ChildPath '..\Public\Get-AssessmentADRBCD.ps1'

        $Source = Get-Content `
            -Path $SourcePath `
            -Raw

        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' |
            Should -BeFalse
    }
}