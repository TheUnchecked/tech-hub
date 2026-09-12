#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADProtectedUsersCoverage' {

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

        function script:New-TestMember {
            param(
                [string]$Name,
                [string]$SamAccountName,
                [string]$DistinguishedName,
                [string]$SID,
                [string]$ObjectClass = 'user'
            )

            [PSCustomObject]@{
                Name              = $Name
                SamAccountName    = $SamAccountName
                DistinguishedName = $DistinguishedName
                SID               = $SID
                ObjectClass       = $ObjectClass
            }
        }

        $script:NewTestPuCoverageProvider = {
            param (
                [hashtable]$MembersByGroup = @{},
                [hashtable]$StatusByGroup = @{}
            )

            $Provider = [PSCustomObject]@{
                Server        = $null
                DomainResult  = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ DNSRoot = 'example.test' }) }
                ForestResult  = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ Name = 'example.test' }) }
                MembersByGroup = $MembersByGroup
                StatusByGroup  = $StatusByGroup
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetGroupMembers -Value {
                param($Identity)

                $Status = 'Available'
                if ($this.StatusByGroup.ContainsKey($Identity)) {
                    $Status = $this.StatusByGroup[$Identity]
                }

                $Members = @()
                if ($this.MembersByGroup.ContainsKey($Identity)) {
                    $Members = @($this.MembersByGroup[$Identity])
                }

                [PSCustomObject]@{
                    Status       = $Status
                    Data         = $Members
                    ErrorType    = $(if ($Status -ne 'Available') { 'AccessDenied' } else { $null })
                    ErrorMessage = $(if ($Status -ne 'Available') { 'Synthetic failure' } else { $null })
                }
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'flags a Domain Admins member not covered by Protected Users' {
        $Uncovered = New-TestMember -Name 'alice' -SamAccountName 'alice' -DistinguishedName 'CN=alice,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1001'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Domain Admins'     = @($Uncovered)
            'Enterprise Admins' = @()
            'Protected Users'   = @()
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-PROTECTED-USERS-COVERAGE'
        $Results[0].Category | Should -Be 'Hardening'
        $Results[0].Severity | Should -Be 'High'
        $Results[0].SamAccountName | Should -Be 'alice'
    }

    It 'does not flag a member already covered by Protected Users' {
        $Covered = New-TestMember -Name 'bob' -SamAccountName 'bob' -DistinguishedName 'CN=bob,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1002'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Domain Admins'     = @($Covered)
            'Enterprise Admins' = @()
            'Protected Users'   = @($Covered)
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)

        $Results.Count | Should -Be 0
    }

    It 'skips nested groups (not signed-in principals)' {
        $NestedGroup = New-TestMember -Name 'Tier0-Admins' -SamAccountName 'Tier0-Admins' -DistinguishedName 'CN=Tier0-Admins,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-2001' -ObjectClass 'group'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Domain Admins'     = @($NestedGroup)
            'Enterprise Admins' = @()
            'Protected Users'   = @()
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)

        $Results.Count | Should -Be 0
    }

    It 'checks every configured privileged group' {
        $UncoveredDA = New-TestMember -Name 'alice' -SamAccountName 'alice' -DistinguishedName 'CN=alice,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1001'
        $UncoveredEA = New-TestMember -Name 'carol' -SamAccountName 'carol' -DistinguishedName 'CN=carol,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1003'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Domain Admins'     = @($UncoveredDA)
            'Enterprise Admins' = @($UncoveredEA)
            'Protected Users'   = @()
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)

        $Results.Count | Should -Be 2
        $Results.Evidence.PrivilegedGroup | Should -Contain 'Domain Admins'
        $Results.Evidence.PrivilegedGroup | Should -Contain 'Enterprise Admins'
    }

    It 'returns structured results when Protected Users membership is unavailable' {
        $Provider = & $script:NewTestPuCoverageProvider -StatusByGroup @{ 'Protected Users' = 'Error' }

        $Result = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)[0]

        $Result.Status | Should -Be 'Error'
    }

    It 'reports one unavailable finding for a privileged group that fails, but still checks the others' {
        $UncoveredEA = New-TestMember -Name 'carol' -SamAccountName 'carol' -DistinguishedName 'CN=carol,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1003'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Enterprise Admins' = @($UncoveredEA)
            'Protected Users'   = @()
        } -StatusByGroup @{
            'Domain Admins' = 'Error'
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)

        $Results.Count | Should -Be 2
        ($Results | Where-Object Title -like 'Protected Users coverage assessment unavailable for Domain Admins*').Count | Should -Be 1
        ($Results | Where-Object SamAccountName -eq 'carol').Count | Should -Be 1
    }

    It 'supports a custom list of privileged groups and Protected Users group name' {
        $Uncovered = New-TestMember -Name 'dave' -SamAccountName 'dave' -DistinguishedName 'CN=dave,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1004'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Tier0-Operators' = @($Uncovered)
            'Custom-PU'       = @()
        }

        $Results = @(
            Get-AssessmentADProtectedUsersCoverage `
                -Provider $Provider `
                -PrivilegedGroups 'Tier0-Operators' `
                -ProtectedUsersGroupName 'Custom-PU'
        )

        $Results.Count | Should -Be 1
    }

    It 'creates a provider when invoked without one' {
        $Uncovered = New-TestMember -Name 'alice' -SamAccountName 'alice' -DistinguishedName 'CN=alice,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1001'

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestPuCoverageProvider -MembersByGroup @{
                'Domain Admins'     = @($Uncovered)
                'Enterprise Admins' = @()
                'Protected Users'   = @()
            }
        }

        $Results = @(Get-AssessmentADProtectedUsersCoverage -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Uncovered = New-TestMember -Name 'alice' -SamAccountName 'alice' -DistinguishedName 'CN=alice,DC=example,DC=test' -SID 'S-1-5-21-1-2-3-1001'

        $Provider = & $script:NewTestPuCoverageProvider -MembersByGroup @{
            'Domain Admins'     = @($Uncovered)
            'Enterprise Admins' = @()
            'Protected Users'   = @()
        }

        $Result = @(Get-AssessmentADProtectedUsersCoverage -Provider $Provider)[0]

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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADProtectedUsersCoverage.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
