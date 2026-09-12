#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADShadowAdminRights' {

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

        function script:New-TestAce {
            param(
                [string]$IdentityReference,
                [string]$ActiveDirectoryRights = 'GenericAll',
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

        $script:NewTestShadowAdminProvider = {
            param (
                [object[]]$DomainRootAces = @(),
                [object[]]$AdminSDHolderAces = @(),
                [string]$DomainDN = 'DC=example,DC=test',
                [hashtable]$StatusByDN
            )

            $AdminSDHolderDN = 'CN=AdminSDHolder,CN=System,{0}' -f $DomainDN

            $ResultsByDN = @{
                $DomainDN       = [PSCustomObject]@{ Status = 'Available'; Data = @($DomainRootAces); ErrorType = $null; ErrorMessage = $null }
                $AdminSDHolderDN = [PSCustomObject]@{ Status = 'Available'; Data = @($AdminSDHolderAces); ErrorType = $null; ErrorMessage = $null }
            }

            if ($null -ne $StatusByDN) {
                foreach ($Key in $StatusByDN.Keys) {
                    $ResultsByDN[$Key] = $StatusByDN[$Key]
                }
            }

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
                ResultsByDN = $ResultsByDN
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetObjectSecurityDescriptor -Value {
                param($Identity)

                if ($this.ResultsByDN.ContainsKey($Identity)) {
                    return $this.ResultsByDN[$Identity]
                }

                return [PSCustomObject]@{ Status = 'Available'; Data = @(); ErrorType = $null; ErrorMessage = $null }
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'flags an unexpected GenericAll grant on the domain root as High' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-shadow' -ActiveDirectoryRights 'GenericAll')

        $Result = @(
            Get-AssessmentADShadowAdminRights -Provider (& $script:NewTestShadowAdminProvider -DomainRootAces $Aces)
        )[0]

        $Result.CheckId | Should -Be 'AD-SHADOW-ADMIN'
        $Result.Category | Should -Be 'PrivilegedAccess'
        $Result.Severity | Should -Be 'High'
        $Result.Evidence.HasHighImpactRight | Should -BeTrue
    }

    It 'flags a GenericWrite-only grant as Medium' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-writer' -ActiveDirectoryRights 'GenericWrite')

        $Result = @(
            Get-AssessmentADShadowAdminRights -Provider (& $script:NewTestShadowAdminProvider -DomainRootAces $Aces)
        )[0]

        $Result.Severity | Should -Be 'Medium'
        $Result.Evidence.HasHighImpactRight | Should -BeFalse
    }

    It 'skips default approved principals' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\Domain Admins' -ActiveDirectoryRights 'GenericAll')

        $Results = @(
            Get-AssessmentADShadowAdminRights -Provider (& $script:NewTestShadowAdminProvider -DomainRootAces $Aces)
        )

        $Results.Count | Should -Be 0
    }

    It 'ignores rights scoped to a specific object type (not the whole object)' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-scoped' -ActiveDirectoryRights 'GenericAll' -ObjectTypeGuid ([guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'))

        $Results = @(
            Get-AssessmentADShadowAdminRights -Provider (& $script:NewTestShadowAdminProvider -DomainRootAces $Aces)
        )

        $Results.Count | Should -Be 0
    }

    It 'assesses both the domain root and AdminSDHolder' {
        $DomainAces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-root' -ActiveDirectoryRights 'GenericAll')
        $AdminSDHolderAces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-sdholder' -ActiveDirectoryRights 'WriteDacl')

        $Results = @(
            Get-AssessmentADShadowAdminRights -Provider (
                & $script:NewTestShadowAdminProvider -DomainRootAces $DomainAces -AdminSDHolderAces $AdminSDHolderAces
            )
        )

        $Results.Count | Should -Be 2
        ($Results | Where-Object { $_.Evidence.TargetObject -eq 'Domain root' }).Evidence.Identity | Should -Be 'EXAMPLE\svc-root'
        ($Results | Where-Object { $_.Evidence.TargetObject -eq 'AdminSDHolder' }).Evidence.Identity | Should -Be 'EXAMPLE\svc-sdholder'
    }

    It 'returns structured results when an ACL cannot be retrieved' {
        $DomainDN = 'DC=example,DC=test'

        $Provider = & $script:NewTestShadowAdminProvider -StatusByDN @{
            $DomainDN = [PSCustomObject]@{ Status = 'Error'; Data = @(); ErrorType = 'AccessDenied'; ErrorMessage = 'Synthetic access denied' }
        }

        $Result = @(Get-AssessmentADShadowAdminRights -Provider $Provider)[0]

        $Result.Status | Should -Be 'Error'
        $Result.Evidence.ErrorType | Should -Be 'AccessDenied'
    }

    It 'handles a missing domain distinguished name' {
        $Provider = & $script:NewTestShadowAdminProvider
        $Provider.DomainResult.Data[0].DistinguishedName = $null

        $Result = @(Get-AssessmentADShadowAdminRights -Provider $Provider)[0]

        $Result.ObjectType | Should -Be 'Domain'
    }

    It 'creates a provider when invoked without one' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-shadow' -ActiveDirectoryRights 'GenericAll')

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestShadowAdminProvider -DomainRootAces $Aces
        }

        $Results = @(Get-AssessmentADShadowAdminRights -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Aces = @(New-TestAce -IdentityReference 'EXAMPLE\svc-shadow' -ActiveDirectoryRights 'GenericAll')

        $Result = @(
            Get-AssessmentADShadowAdminRights -Provider (& $script:NewTestShadowAdminProvider -DomainRootAces $Aces)
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADShadowAdminRights.ps1'
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
