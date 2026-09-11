#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADDCSyncRights' {

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

        $script:GetChangesGuid = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        $script:GetChangesAllGuid = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

        function script:New-TestAce {
            param(
                [string]$IdentityReference,
                [string]$ActiveDirectoryRights = 'ExtendedRight',
                [guid]$ObjectTypeGuid = [guid]::Empty,
                [string]$AccessControlType = 'Allow'
            )

            [PSCustomObject]@{
                IdentityReference     = $IdentityReference
                ActiveDirectoryRights = $ActiveDirectoryRights
                ObjectTypeGuid        = $ObjectTypeGuid
                AccessControlType     = $AccessControlType
                IsInherited           = $false
            }
        }

        $script:NewTestDCSyncProvider = {
            param (
                [object[]]$Aces = @(),
                [string]$AclStatus = 'Available',
                [string]$AclErrorType,
                [string]$AclErrorMessage,
                [string]$DomainDN = 'DC=example,DC=test'
            )

            $Provider = [PSCustomObject]@{
                Server       = $null
                DomainResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ DNSRoot = 'example.test'; DistinguishedName = $DomainDN })
                }
                ForestResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ Name = 'example.test' })
                }
                AclResult = [PSCustomObject]@{
                    Status       = $AclStatus
                    Data         = @($Aces)
                    ErrorType    = $AclErrorType
                    ErrorMessage = $AclErrorMessage
                }
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetObjectSecurityDescriptor -Value {
                param($Identity)
                return $this.AclResult
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'flags an unexpected principal with full DCSync rights as Critical' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesGuid
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesAllGuid
        )

        $Result = @(
            Get-AssessmentADDCSyncRights -Provider (& $script:NewTestDCSyncProvider -Aces $Aces)
        )[0]

        $Result.CheckId | Should -Be 'AD-DCSYNC-RIGHTS'
        $Result.Category | Should -Be 'PrivilegedAccess'
        $Result.Severity | Should -Be 'Critical'
        $Result.Evidence.HasFullDCSync | Should -BeTrue
    }

    It 'flags a partial grant as High' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\svc-partial' -ObjectTypeGuid $script:GetChangesGuid
        )

        $Result = @(
            Get-AssessmentADDCSyncRights -Provider (& $script:NewTestDCSyncProvider -Aces $Aces)
        )[0]

        $Result.Severity | Should -Be 'High'
        $Result.Evidence.HasFullDCSync | Should -BeFalse
    }

    It 'skips default approved principals' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\Domain Admins' -ObjectTypeGuid $script:GetChangesGuid
            New-TestAce -IdentityReference 'EXAMPLE\Domain Admins' -ObjectTypeGuid $script:GetChangesAllGuid
            New-TestAce -IdentityReference 'NT AUTHORITY\SYSTEM' -ObjectTypeGuid $script:GetChangesGuid
        )

        $Results = @(
            Get-AssessmentADDCSyncRights -Provider (& $script:NewTestDCSyncProvider -Aces $Aces)
        )

        $Results.Count | Should -Be 0
    }

    It 'ignores Deny ACEs and unrelated extended rights' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\denied-user' -ObjectTypeGuid $script:GetChangesGuid -AccessControlType 'Deny'
            New-TestAce -IdentityReference 'EXAMPLE\unrelated-user' -ObjectTypeGuid ([guid]'ab721a53-1e2f-11d0-9819-00aa0040529b')
        )

        $Results = @(
            Get-AssessmentADDCSyncRights -Provider (& $script:NewTestDCSyncProvider -Aces $Aces)
        )

        $Results.Count | Should -Be 0
    }

    It 'supports a custom ApprovedPrincipalPatterns list' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\svc-adconnect' -ObjectTypeGuid $script:GetChangesGuid
            New-TestAce -IdentityReference 'EXAMPLE\svc-adconnect' -ObjectTypeGuid $script:GetChangesAllGuid
        )

        $Results = @(
            Get-AssessmentADDCSyncRights `
                -Provider (& $script:NewTestDCSyncProvider -Aces $Aces) `
                -ApprovedPrincipalPatterns '*\svc-adconnect'
        )

        $Results.Count | Should -Be 0
    }

    It 'returns structured results when the ACL cannot be retrieved' {
        $Result = @(
            Get-AssessmentADDCSyncRights -Provider (
                & $script:NewTestDCSyncProvider -AclStatus 'Error' -AclErrorType 'AccessDenied' -AclErrorMessage 'Synthetic access denied'
            )
        )[0]

        $Result.Status | Should -Be 'Error'
        $Result.Evidence.ErrorType | Should -Be 'AccessDenied'
    }

    It 'handles a missing domain distinguished name' {
        $Provider = & $script:NewTestDCSyncProvider
        $Provider.DomainResult.Data[0].DistinguishedName = $null

        $Result = @(Get-AssessmentADDCSyncRights -Provider $Provider)[0]

        $Result.ObjectType | Should -Be 'Domain'
    }

    It 'creates a provider when invoked without one' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesGuid
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesAllGuid
        )

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestDCSyncProvider -Aces $Aces
        }

        $Results = @(Get-AssessmentADDCSyncRights -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Aces = @(
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesGuid
            New-TestAce -IdentityReference 'EXAMPLE\svc-sync' -ObjectTypeGuid $script:GetChangesAllGuid
        )

        $Result = @(
            Get-AssessmentADDCSyncRights -Provider (& $script:NewTestDCSyncProvider -Aces $Aces)
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADDCSyncRights.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\bSet-Acl\b' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
