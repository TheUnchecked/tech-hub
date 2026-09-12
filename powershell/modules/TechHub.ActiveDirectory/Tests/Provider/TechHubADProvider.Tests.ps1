#requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'TechHubADProvider' {

    BeforeAll {

        # ============================================================
        # RESOLVE PATHS
        # ============================================================

        $TestFile = $PSCommandPath

        if ([string]::IsNullOrWhiteSpace($TestFile)) {
            throw 'Unable to determine test file path.'
        }

        $TestFile = (Resolve-Path -LiteralPath $TestFile -ErrorAction Stop).Path

        $ProviderTestsRoot = Split-Path -Parent $TestFile
        $TestsRoot         = Split-Path -Parent $ProviderTestsRoot
        $ModuleRoot        = Split-Path -Parent $TestsRoot

        $ModuleManifest = Join-Path `
            $ModuleRoot `
            'TechHub.ActiveDirectory.psd1'

        $ProviderPath = Join-Path `
            $ModuleRoot `
            'Providers\ActiveDirectory\TechHubADProvider.ps1'

        # ============================================================
        # VALIDATE PATHS
        # ============================================================

        if (-not (Test-Path -LiteralPath $ModuleManifest)) {
            throw "Module manifest not found: $ModuleManifest"
        }

        if (-not (Test-Path -LiteralPath $ProviderPath)) {
            throw "Provider source not found: $ProviderPath"
        }

        # ============================================================
        # CLEAN MODULE
        # ============================================================

        Remove-Module `
            TechHub.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue

        # ============================================================
        # CREATE AD COMMAND STUBS
        #
        # These exist only so Pester can mock them.
        # The real ActiveDirectory module is NOT required.
        # ============================================================

        function global:Get-ADDomain {
            param(
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADForest {
            param(
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADDomainController {
            param(
                [string]$Filter,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADObject {
            param(
                [string]$LDAPFilter,
                [string]$Identity,
                [string]$SearchBase,
                [string[]]$Properties,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADGroup {
            param(
                [string]$Filter,
                [string]$SearchBase,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADGroupMember {
            param(
                [string]$Identity,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADDefaultDomainPasswordPolicy {
            param(
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADFineGrainedPasswordPolicy {
            param(
                [string]$Filter,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        function global:Get-ADOptionalFeature {
            param(
                [string]$Filter,
                [string]$Server,
                [string]$ErrorAction
            )
        }

        # ============================================================
        # IMPORT MODULE
        # ============================================================

        Import-Module `
            $ModuleManifest `
            -Force `
            -ErrorAction Stop
    }

    AfterAll {

        Remove-Item `
            Function:\Get-ADDomain `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADForest `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADDomainController `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADObject `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADGroup `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADGroupMember `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADDefaultDomainPasswordPolicy `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADFineGrainedPasswordPolicy `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            Function:\Get-ADOptionalFeature `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Module `
            TechHub.ActiveDirectory `
            -Force `
            -ErrorAction SilentlyContinue
    }

    BeforeEach {

        # ============================================================
        # TEST DATA
        # ============================================================

        $Script:Domain = [PSCustomObject]@{
            DNSRoot           = 'example.test'
            NetBIOSName       = 'EXAMPLE'
            DistinguishedName = 'DC=example,DC=test'
            DomainMode        = 'Windows2016Domain'
        }

        $Script:Forest = [PSCustomObject]@{
            Name       = 'example.test'
            ForestMode = 'Windows2016Forest'
            RootDomain = 'example.test'
            Domains    = @(
                'example.test'
            )
        }

        $Script:Object = [PSCustomObject]@{
            Name                       = 'APP01'
            SamAccountName             = 'APP01$'
            DistinguishedName          = 'CN=APP01,DC=example,DC=test'
            ObjectGUID                 = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass                = @(
                'top'
                'computer'
            )
            ObjectCategory             = 'computer'
            UserAccountControl         = 0
            ServicePrincipalName       = @(
                'HOST/APP01.example.test'
            )
            MemberOf                   = @(
                'CN=Servers,DC=example,DC=test'
            )
            'msDS-AllowedToDelegateTo'  = @(
                'HTTP/api.example.test'
            )
            SID                        = 'S-1-5-21-100-200-300-1101'
        }

        $Script:Group = [PSCustomObject]@{
            Name              = 'Domain Admins'
            SamAccountName    = 'Domain Admins'
            DistinguishedName = 'CN=Domain Admins,CN=Users,DC=example,DC=test'
            ObjectGUID        = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass       = @(
                'top'
                'group'
            )
        }

        $Script:Member = [PSCustomObject]@{
            Name               = 'alice'
            SamAccountName     = 'alice'
            DistinguishedName  = 'CN=alice,CN=Users,DC=example,DC=test'
            ObjectGUID         = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass        = @(
                'top'
                'person'
                'user'
            )
            UserAccountControl = 0
            SID                = 'S-1-5-21-100-200-300-1102'
        }

        $Script:PasswordPolicy = [PSCustomObject]@{
            DistinguishedName           = 'DC=example,DC=test'
            MinPasswordLength           = 14
            ComplexityEnabled           = $true
            ReversibleEncryptionEnabled = $false
            LockoutThreshold            = 10
        }

        $Script:FineGrainedPasswordPolicy = [PSCustomObject]@{
            Name              = 'Tier0-PSO'
            MinPasswordLength = 20
            ComplexityEnabled = $true
        }

        $Script:OptionalFeature = [PSCustomObject]@{
            Name          = 'Recycle Bin Feature'
            EnabledScopes = @('DC=example,DC=test')
        }

        # ============================================================
        # MOCK AVAILABILITY CHECK
        #
        # The real ActiveDirectory module is intentionally absent
        # on this workstation.
        #
        # For unit tests we simulate its availability.
        # ============================================================

        Mock `
            Test-TechHubADActiveDirectoryAvailability `
            -ModuleName TechHub.ActiveDirectory {
                $true
            }

        # ============================================================
        # MOCK AD COMMANDS
        # ============================================================

        Mock `
            Get-ADDomain `
            -ModuleName TechHub.ActiveDirectory {
                $Script:Domain
            }

        Mock `
            Get-ADForest `
            -ModuleName TechHub.ActiveDirectory {
                $Script:Forest
            }

        Mock `
            Get-ADDomainController `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:Object
                )
            }

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:Object
                )
            }

        Mock `
            Get-ADGroup `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:Group
                )
            }

        Mock `
            Get-ADGroupMember `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:Member
                )
            }

        Mock `
            Get-ADDefaultDomainPasswordPolicy `
            -ModuleName TechHub.ActiveDirectory {
                $Script:PasswordPolicy
            }

        Mock `
            Get-ADFineGrainedPasswordPolicy `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:FineGrainedPasswordPolicy
                )
            }

        Mock `
            Get-ADOptionalFeature `
            -ModuleName TechHub.ActiveDirectory {
                @(
                    $Script:OptionalFeature
                )
            }
    }

    # ================================================================
    # 1
    # ================================================================

    It 'creates a provider without contacting Active Directory' {

        $Provider = New-AssessmentADProvider

        $Provider.GetType().Name |
            Should -Be 'TechHubADProvider'

        $Provider.Server |
            Should -BeNullOrEmpty

        Should -Invoke `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory `
            -Times 0
    }

    # ================================================================
    # 2
    # ================================================================

    It 'reports module availability' {

        $Provider = New-AssessmentADProvider

        $Provider.GetDomainInformation().Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 3
    # ================================================================

    It 'retrieves domain information' {

        $Result = (
            New-AssessmentADProvider
        ).GetDomainInformation()

        $Result.Data[0].DNSRoot |
            Should -Be 'example.test'

        $Result.Data[0].NetBIOSName |
            Should -Be 'EXAMPLE'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 4
    # ================================================================

    It 'retrieves forest information' {

        $Result = (
            New-AssessmentADProvider
        ).GetForestInformation()

        $Result.Data[0].Name |
            Should -Be 'example.test'

        $Result.Data[0].RootDomain |
            Should -Be 'example.test'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 5
    # ================================================================

    It 'retrieves domain controllers' {

        $Result = (
            New-AssessmentADProvider
        ).GetDomainControllers()

        $Result.Data[0].Name |
            Should -Be 'APP01'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 5b
    # ================================================================

    It 'retrieves the default domain password policy' {

        $Result = (
            New-AssessmentADProvider
        ).GetDefaultDomainPasswordPolicy()

        $Result.Data[0].MinPasswordLength |
            Should -Be 14

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 5c
    # ================================================================

    It 'retrieves fine-grained password policies' {

        $Result = (
            New-AssessmentADProvider
        ).GetFineGrainedPasswordPolicies()

        $Result.Data[0].Name |
            Should -Be 'Tier0-PSO'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 5cc
    # ================================================================

    It 'retrieves optional features' {

        $Result = (
            New-AssessmentADProvider
        ).GetOptionalFeatures("Name -eq 'Recycle Bin Feature'")

        $Result.Data[0].Name |
            Should -Be 'Recycle Bin Feature'

        $Result.Data[0].EnabledScopes |
            Should -Contain 'DC=example,DC=test'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 5d
    # ================================================================

    It 'retrieves and normalizes the security descriptor of an object' {

        $SyntheticSecurityDescriptor = [PSCustomObject]@{
            Access = @(
                [PSCustomObject]@{
                    IdentityReference     = 'EXAMPLE\Domain Admins'
                    ActiveDirectoryRights = 'GenericAll'
                    ObjectType            = [guid]::Empty
                    AccessControlType     = 'Allow'
                    IsInherited           = $false
                }
                [PSCustomObject]@{
                    IdentityReference     = 'EXAMPLE\svc-backup'
                    ActiveDirectoryRights = 'ExtendedRight'
                    ObjectType            = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                    AccessControlType     = 'Allow'
                    IsInherited           = $false
                }
            )
        }

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {
                [PSCustomObject]@{
                    DistinguishedName    = 'DC=example,DC=test'
                    nTSecurityDescriptor = $SyntheticSecurityDescriptor
                }
            }

        $Result = (
            New-AssessmentADProvider
        ).GetObjectSecurityDescriptor('DC=example,DC=test')

        $Result.Status |
            Should -Be 'Available'

        $Result.Data.Count |
            Should -Be 2

        $Result.Data[0].IdentityReference |
            Should -Be 'EXAMPLE\Domain Admins'

        $Result.Data[1].ObjectTypeGuid |
            Should -Be ([guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
    }

    # ================================================================
    # 6
    # ================================================================

    It 'retrieves and normalizes AD objects' {

        $Result = (
            New-AssessmentADProvider
        ).GetADObjects(
            '(objectClass=computer)',
            $null,
            @(
                'Name'
                'SamAccountName'
                'ServicePrincipalName'
                'msDS-AllowedToDelegateTo'
            )
        )

        $Result.Data[0].Name |
            Should -Be 'APP01'

        $Result.Data[0].SamAccountName |
            Should -Be 'APP01$'

        @(
            $Result.Data[0].ServicePrincipalName
        ).Count |
            Should -Be 1

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 7
    # ================================================================

    It 'preserves one constrained delegation target as a string array' {

        $Provider = New-AssessmentADProvider

        $Result = $Provider.GetADObjects(
            '(objectClass=computer)',
            $null,
            @(
                'Name'
                'msDS-AllowedToDelegateTo'
            )
        )

        $Object = $Result.Data[0]

        $Object.'msDS-AllowedToDelegateTo'.GetType().FullName |
            Should -Be 'System.String[]'

        $Object.'msDS-AllowedToDelegateTo'.Count |
            Should -Be 1

        $Object.'msDS-AllowedToDelegateTo'[0] |
            Should -Be 'HTTP/api.example.test'
    }

    # ================================================================
    # 8
    # ================================================================

    It 'preserves multiple delegation targets in source order' {

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

                [PSCustomObject]@{
                    Name = 'APP01'

                    'msDS-AllowedToDelegateTo' = @(
                        'HTTP/first.example.test'
                        'LDAP/second.example.test'
                    )

                    ServicePrincipalName = @(
                        'HOST/APP01.example.test'
                    )
                }
            }

        $Object = (
            New-AssessmentADProvider
        ).GetADObjects(
            '(objectClass=computer)',
            $null,
            @(
                'msDS-AllowedToDelegateTo'
            )
        ).Data[0]

        $Object.'msDS-AllowedToDelegateTo'.Count |
            Should -Be 2

        $Object.'msDS-AllowedToDelegateTo'[0] |
            Should -Be 'HTTP/first.example.test'

        $Object.'msDS-AllowedToDelegateTo'[1] |
            Should -Be 'LDAP/second.example.test'
    }

    # ================================================================
    # 9
    # ================================================================

    It 'normalizes a scalar delegation target to a string array' {

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

                [PSCustomObject]@{
                    Name = 'SCALAR'

                    'msDS-AllowedToDelegateTo' =
                        'HTTP/single.example.test'
                }
            }

        $Object = (
            New-AssessmentADProvider
        ).GetADObjects(
            '(objectClass=computer)',
            $null,
            @(
                'msDS-AllowedToDelegateTo'
            )
        ).Data[0]

        $Object.'msDS-AllowedToDelegateTo'.GetType().FullName |
            Should -Be 'System.String[]'

        $Object.'msDS-AllowedToDelegateTo'[0] |
            Should -Be 'HTTP/single.example.test'
    }

    # ================================================================
    # 10
    # ================================================================

    It 'returns null when the delegation attribute is absent, null, or empty' {

        foreach ($SourceObject in @(
            [PSCustomObject]@{
                Name = 'ABSENT'
            }

            [PSCustomObject]@{
                Name = 'NULL'
                'msDS-AllowedToDelegateTo' = $null
            }

            [PSCustomObject]@{
                Name = 'EMPTY'
                'msDS-AllowedToDelegateTo' = @()
            }
        )) {

            Mock `
                Get-ADObject `
                -ModuleName TechHub.ActiveDirectory {
                    $SourceObject
                }

            $Object = (
                New-AssessmentADProvider
            ).GetADObjects(
                '(objectClass=computer)',
                $null,
                @(
                    'msDS-AllowedToDelegateTo'
                )
            ).Data[0]

            $Object.PSObject.Properties.Name |
                Should -Contain 'msDS-AllowedToDelegateTo'

            $Object.'msDS-AllowedToDelegateTo' |
                Should -BeNullOrEmpty
        }
    }

    # ================================================================
    # 11
    # ================================================================

    It 'passes requested properties through to Get-ADObject' {

        $RequestedProperties = @(
            'Name'
            'msDS-AllowedToDelegateTo'
        )

        $Provider = New-AssessmentADProvider

        $Provider.GetADObjects(
            '(objectClass=computer)',
            'DC=example,DC=test',
            $RequestedProperties
        ) | Out-Null

        Should -Invoke `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {

                $Properties -contains 'msDS-AllowedToDelegateTo' -and
                $Properties -contains 'Name' -and
                $SearchBase -eq 'DC=example,DC=test'
            } `
            -Times 1
    }

    # ================================================================
    # 12
    # ================================================================

    It 'retrieves groups and group members' {

        $Provider = New-AssessmentADProvider

        $GroupResult = $Provider.GetGroups(
            $null,
            $null
        )

        $MemberResult = $Provider.GetGroupMembers(
            'CN=Domain Admins,CN=Users,DC=example,DC=test'
        )

        $GroupResult.Data[0].Name |
            Should -Be 'Domain Admins'

        $MemberResult.Data[0].SamAccountName |
            Should -Be 'alice'
    }

    # ================================================================
    # 13
    # ================================================================

    It 'reports available provider status after successful operations' {

        $Provider = New-AssessmentADProvider

        $Provider.GetDomainInformation() |
            Out-Null

        $Provider.GetForestInformation() |
            Out-Null

        $Provider.GetProviderStatus().Status |
            Should -Be 'Available'
    }

    # ================================================================
    # 14
    # ================================================================

    It 'reports partial status when one operation fails after success' {

        $Provider = New-AssessmentADProvider

        $Provider.GetDomainInformation() |
            Out-Null

        Mock `
            Get-ADDomainController `
            -ModuleName TechHub.ActiveDirectory {

                throw [System.Exception]::new(
                    'server unavailable'
                )
            }

        $Provider.GetDomainControllers().Status |
            Should -Be 'Error'

        $Provider.GetProviderStatus().Status |
            Should -Be 'Partial'
    }

    # ================================================================
    # 15
    # ================================================================

    It 'reports NotAvailable when the ActiveDirectory module is unavailable' {

        Mock `
            Test-TechHubADActiveDirectoryAvailability `
            -ModuleName TechHub.ActiveDirectory {
                $false
            }

        $Result = (
            New-AssessmentADProvider
        ).GetDomainInformation()

        $Result.Status |
            Should -Be 'NotAvailable'

        $Result.ErrorType |
            Should -Be 'ModuleUnavailable'
    }

    # ================================================================
    # 16
    # ================================================================

    It 'classifies access denied, LDAP, not found and server errors' {

        $Provider = New-AssessmentADProvider

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

                throw [System.Exception]::new(
                    'Access denied'
                )
            }

        $Provider.GetADObjects(
            '(objectClass=*)',
            $null,
            @(
                'Name'
            )
        ).ErrorType |
            Should -Be 'AccessDenied'

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

                throw [System.Exception]::new(
                    'LDAP error'
                )
            }

        $Provider.GetADObjects(
            '(objectClass=*)',
            $null,
            @(
                'Name'
            )
        ).ErrorType |
            Should -Be 'LdapError'

        Mock `
            Get-ADGroup `
            -ModuleName TechHub.ActiveDirectory {

                throw [System.Exception]::new(
                    'object not found'
                )
            }

        $Provider.GetGroups(
            $null,
            $null
        ).ErrorType |
            Should -Be 'ObjectNotFound'

        Mock `
            Get-ADForest `
            -ModuleName TechHub.ActiveDirectory {

                throw [System.Exception]::new(
                    'domain controller unreachable'
                )
            }

        $Provider.GetForestInformation().ErrorType |
            Should -Be 'ServerUnavailable'
    }

    # ================================================================
    # 17
    # ================================================================

    It 'propagates Server to read operations' {

        $Provider = New-AssessmentADProvider `
            -Server 'dc01.example.test'

        $Provider.GetDomainInformation() |
            Out-Null

        $Provider.GetADObjects(
            '(objectClass=*)',
            'DC=example,DC=test',
            @(
                'Name'
            )
        ) | Out-Null

        Should -Invoke `
            Get-ADDomain `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test'
            } `
            -Times 1

        Should -Invoke `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test' -and
                $SearchBase -eq 'DC=example,DC=test'
            } `
            -Times 1
    }

    # ================================================================
    # 18
    # ================================================================

    It 'returns null for missing properties without throwing' {

        Mock `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory {

                [PSCustomObject]@{
                    Name = 'MINIMAL'
                }
            }

        $Object = (
            New-AssessmentADProvider
        ).GetADObjects(
            '(objectClass=*)',
            $null,
            @(
                'Name'
            )
        ).Data[0]

        $Object.Name |
            Should -Be 'MINIMAL'

        $Object.SamAccountName |
            Should -BeNullOrEmpty

        @(
            $Object.ServicePrincipalName
        ).Count |
            Should -Be 0
    }

    # ================================================================
    # 19
    # ================================================================

    It 'is read-only and contains no dynamic or modifying commands' {

        $Source = Get-Content `
            -Path (
                Join-Path `
                    $ModuleRoot `
                    'Providers\ActiveDirectory\TechHubADProvider.ps1'
            ) `
            -Raw

        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' |
            Should -BeFalse

        $DynamicMarkers = @(
            'Invoke-Expression'
            'ScriptBlock'
            'Start-Process'
        )

        foreach ($Marker in $DynamicMarkers) {

            $Source -match [regex]::Escape($Marker) |
                Should -BeFalse
        }

        (
            New-AssessmentADProvider
        ).GetDomainInformation().IsReadOnly |
            Should -BeTrue
    }
}