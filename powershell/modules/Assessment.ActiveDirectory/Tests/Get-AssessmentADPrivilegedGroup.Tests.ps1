#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADPrivilegedGroup' {

    BeforeAll {

        $ModulePath = Join-Path `
            -Path $PSScriptRoot `
            -ChildPath '..'

        Import-Module `
            -Name $ModulePath `
            -Force `
            -ErrorAction Stop

        # ------------------------------------------------------------
        # Test-only Active Directory command stubs.
        #
        # The tests must not require RSAT / ActiveDirectory module.
        # Pester needs the commands to exist before they are mocked.
        # ------------------------------------------------------------

        if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
            function global:Get-ADDomain {
                param(
                    [string]$Server
                )
            }
        }

        if (-not (Get-Command Get-ADForest -ErrorAction SilentlyContinue)) {
            function global:Get-ADForest {
                param(
                    [string]$Server
                )
            }
        }

        if (-not (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)) {
            function global:Get-ADGroup {
                param(
                    [string]$Identity,
                    [string]$Server,
                    [string]$SearchBase,
                    [string]$Filter
                )
            }
        }

        if (-not (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue)) {
            function global:Get-ADGroupMember {
                param(
                    [string]$Identity,
                    [string]$Server
                )
            }
        }

        if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
            function global:Get-ADObject {
                param(
                    [string]$Identity,
                    [string[]]$Properties,
                    [string]$Server
                )
            }
        }
    }

    AfterAll {

        Remove-Module `
            -Name Assessment.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue

        foreach ($CommandName in @(
            'Get-ADDomain'
            'Get-ADForest'
            'Get-ADGroup'
            'Get-ADGroupMember'
            'Get-ADObject'
        )) {
            $Command = Get-Command `
                -Name $CommandName `
                -CommandType Function `
                -ErrorAction SilentlyContinue

            if ($null -ne $Command -and
                $Command.Source -eq 'Global') {

                Remove-Item `
                    -Path "Function:\$CommandName" `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }

    BeforeEach {

        $Script:Group = [PSCustomObject]@{
            Name              = 'Domain Admins'
            SamAccountName    = 'Domain Admins'
            DistinguishedName = 'CN=Domain Admins,CN=Users,DC=example,DC=test'
            ObjectGUID        = [guid]'77777777-7777-7777-7777-777777777777'
            ObjectClass       = @('top', 'group')
        }

        $Script:User = [PSCustomObject]@{
            Name              = 'alice'
            ObjectClass       = @('top', 'person', 'user')
            ObjectGUID        = [guid]::NewGuid()
            DistinguishedName = 'CN=alice,CN=Users,DC=example,DC=test'
            SamAccountName    = 'alice'
            SID               = 'S-1-5-21-100-200-300-1101'
        }

        $Script:Computer = [PSCustomObject]@{
            Name              = 'WEB01$'
            ObjectClass       = @('top', 'person', 'computer')
            ObjectGUID        = [guid]::NewGuid()
            DistinguishedName = 'CN=WEB01,OU=Servers,DC=example,DC=test'
            SamAccountName    = 'WEB01$'
            SID               = 'S-1-5-21-100-200-300-1102'
        }

        $Script:Details = @{
            'CN=alice,CN=Users,DC=example,DC=test' = [PSCustomObject]@{
                Name                 = 'alice'
                SamAccountName       = 'alice'
                ObjectClass          = @('user')
                ObjectGUID           = $Script:User.ObjectGUID
                DistinguishedName    = $Script:User.DistinguishedName
                Enabled              = $true
                adminCount           = 0
                PasswordNeverExpires = $false
                SID                  = 'S-1-5-21-100-200-300-1101'
            }

            'CN=WEB01,OU=Servers,DC=example,DC=test' = [PSCustomObject]@{
                Name                 = 'WEB01$'
                SamAccountName       = 'WEB01$'
                ObjectClass          = @('computer')
                ObjectGUID           = $Script:Computer.ObjectGUID
                DistinguishedName    = $Script:Computer.DistinguishedName
                Enabled              = $true
                adminCount           = 0
                PasswordNeverExpires = $false
                SID                  = 'S-1-5-21-100-200-300-1102'
            }
        }

        Mock Get-ADDomain `
            -ModuleName Assessment.ActiveDirectory {
                [PSCustomObject]@{
                    DNSRoot = 'example.test'
                }
            }

        Mock Get-ADForest `
            -ModuleName Assessment.ActiveDirectory {
                [PSCustomObject]@{
                    Name = 'example.test'
                }
            }

        Mock Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory {
                @($Script:Group)
            }

        Mock Get-ADGroupMember `
            -ModuleName Assessment.ActiveDirectory {
                @($Script:User)
            }

        Mock Get-ADObject `
            -ModuleName Assessment.ActiveDirectory {
                if ($Script:Details.ContainsKey($Identity)) {
                    $Script:Details[$Identity]
                }
            }
    }

    It 'finds a privileged group and normalizes a direct user member' {

        $Result = @(Get-AssessmentADPrivilegedGroup)[0]

        $Result.Evidence.MemberObjectType |
            Should -Be 'User'

        $Result.Evidence.MembershipType |
            Should -Be 'Direct'
    }

    It 'handles a computer member' {

        $Script:User = $Script:Computer

        (
            Get-AssessmentADPrivilegedGroup |
                Select-Object -First 1
        ).Evidence.MemberObjectType |
            Should -Be 'Computer'
    }

    It 'handles nested groups and membership paths' {

        $Nested = [PSCustomObject]@{
            Name              = 'Tier2-Admins'
            ObjectClass       = @('group')
            ObjectGUID        = [guid]::NewGuid()
            DistinguishedName = 'CN=Tier2-Admins,OU=Groups,DC=example,DC=test'
            SamAccountName    = 'Tier2-Admins'
            SID               = 'S-1-5-21-100-200-300-1103'
        }

        $Script:User = $Nested

        Mock Get-ADGroupMember `
            -ModuleName Assessment.ActiveDirectory {
                if ($Identity -eq $Script:Group.DistinguishedName) {
                    @($Nested)
                }
                else {
                    @($Script:Computer)
                }
            }

        $Results = @(Get-AssessmentADPrivilegedGroup)

        $Results.Count |
            Should -Be 2

        (
            $Results |
                Where-Object {
                    $_.Evidence.MembershipType -eq 'Indirect'
                }
        ).Evidence.MembershipPath.Count |
            Should -BeGreaterThan 0
    }

    It 'prevents cycles in nested groups' {

        $A = [PSCustomObject]@{
            Name              = 'GroupA'
            ObjectClass       = @('group')
            ObjectGUID        = [guid]::NewGuid()
            DistinguishedName = 'CN=GroupA,DC=example,DC=test'
            SamAccountName    = 'GroupA'
            SID               = 'S-1-5-21-100-200-300-1104'
        }

        Mock Get-ADGroupMember `
            -ModuleName Assessment.ActiveDirectory {
                if ($Identity -eq $Script:Group.DistinguishedName) {
                    @($A)
                }
                else {
                    @($A)
                }
            }

        Mock Get-ADObject `
            -ModuleName Assessment.ActiveDirectory {
                [PSCustomObject]@{
                    Name              = 'GroupA'
                    ObjectClass       = @('group')
                    DistinguishedName = 'CN=GroupA,DC=example,DC=test'
                    Enabled           = $true
                }
            }

        @(Get-AssessmentADPrivilegedGroup).Count |
            Should -Be 1
    }

    It 'handles unresolved members, disabled accounts, adminCount and password expiry' {

        Mock Get-ADObject `
            -ModuleName Assessment.ActiveDirectory {
                [PSCustomObject]@{
                    Name                 = 'alice'
                    SamAccountName       = 'alice'
                    ObjectClass          = @('user')
                    DistinguishedName    = $Script:User.DistinguishedName
                    Enabled              = $false
                    adminCount           = 1
                    PasswordNeverExpires = $true
                    SID                  = $Script:User.SID
                }
            }

        $Result = @(Get-AssessmentADPrivilegedGroup -IncludeDisabled)[0]

        $Result.Evidence.Enabled |
            Should -BeFalse

        $Result.Evidence.AdminCount |
            Should -Be 1

        $Result.Evidence.PasswordNeverExpires |
            Should -BeTrue

        $Result.Severity |
            Should -Be 'High'

        $Result.IsReadOnly |
            Should -BeTrue
    }

    It 'handles an unresolved member without failing the assessment' {

        Mock Get-ADObject `
            -ModuleName Assessment.ActiveDirectory {
                throw [System.Exception]::new('SID not resolved')
            }

        $Result = @(Get-AssessmentADPrivilegedGroup -IncludeDisabled)[0]

        $Result.Confidence |
            Should -Be 'Medium'

        $Result.Evidence.MemberName |
            Should -Be 'alice'
    }

    It 'classifies approved, excluded and service account patterns' {

        (
            Get-AssessmentADPrivilegedGroup `
                -ApprovedMemberPatterns 'alice'
        ).Severity |
            Should -Be 'Informational'

        (
            Get-AssessmentADPrivilegedGroup `
                -ExcludedMemberPatterns 'alice'
        ).Status |
            Should -Be 'NotApplicable'

        (
            Get-AssessmentADPrivilegedGroup `
                -ServiceAccountPatterns 'alice'
        ).Evidence.IsServiceAccount |
            Should -BeTrue
    }

    It 'handles missing groups and empty groups' {

        Mock Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory {
                @()
            }

        @(Get-AssessmentADPrivilegedGroup).Count |
            Should -Be 0

        Mock Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory {
                @($Script:Group)
            }

        Mock Get-ADGroupMember `
            -ModuleName Assessment.ActiveDirectory {
                @()
            }

        (
            Get-AssessmentADPrivilegedGroup |
                Select-Object -First 1
        ).Severity |
            Should -Be 'Informational'
    }

    It 'handles empty results and LDAP/access errors' {

        Mock Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory {
                @()
            }

        @(Get-AssessmentADPrivilegedGroup).Count |
            Should -Be 0

        Mock Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory {
                throw [System.Exception]::new('Access denied')
            }

        @(Get-AssessmentADPrivilegedGroup -ErrorAction SilentlyContinue).Count |
            Should -Be 0
    }

    It 'supports verbose, server, search base and group extension' {

        {
            Get-AssessmentADPrivilegedGroup `
                -Verbose `
                -Server 'dc01.example.test' `
                -SearchBase 'OU=Groups,DC=example,DC=test' `
                -GroupPatterns 'Custom-*' |
                Out-Null
        } |
            Should -Not -Throw

        Should -Invoke `
            Get-ADGroup `
            -ModuleName Assessment.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test' -and
                $SearchBase -eq 'OU=Groups,DC=example,DC=test'
            } `
            -Times 1
    }

    It 'returns the complete contract and contains no AD modification cmdlets' {

        $Result = @(Get-AssessmentADPrivilegedGroup)[0]

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

        $Result.Category |
            Should -Be 'PrivilegedAccess'

        $Source = Get-Content `
            (Join-Path `
                $PSScriptRoot `
                '..\Public\Get-AssessmentADPrivilegedGroup.ps1') `
            -Raw

        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' |
            Should -BeFalse
    }
}