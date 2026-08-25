#requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'TechHubADProvider' {

    BeforeAll {

        # ============================================================
        # RESOLVE MODULE PATH
        # ============================================================

        $TestFile = $PSCommandPath

        if ([string]::IsNullOrWhiteSpace($TestFile)) {
            throw 'Unable to determine the test file path.'
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
        # AD COMMAND STUBS
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
                [string[]]$Properties,
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

        # ============================================================
        # IMPORT MODULE
        # ============================================================

        Import-Module `
            $ModuleManifest `
            -Force `
            -ErrorAction Stop

        # ============================================================
        # MOCK AD MODULE AVAILABILITY
        #
        # The real ActiveDirectory module is not installed on the
        # development workstation. Unit tests must therefore simulate
        # its availability.
        # ============================================================

        Mock `
            Test-TechHubADActiveDirectoryAvailability `
            -ModuleName TechHub.ActiveDirectory {
                $true
            }
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
            'msDS-AllowedToDelegateTo' = @(
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
    }

    # ================================================================
    # PROVIDER CREATION
    # ================================================================

    It 'creates a provider without contacting Active Directory' {

        $Provider = New-TechHubADProvider

        $Provider.GetType().Name |
            Should -Be 'TechHubADProvider'

        $Provider.Server |
            Should -BeNullOrEmpty

        Assert-MockCalled `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory `
            -Times 0
    }

    # ================================================================
    # MODULE AVAILABILITY
    # ================================================================

    It 'reports module availability' {

        $Provider = New-TechHubADProvider

        $Provider.GetDomainInformation().Status |
            Should -Be 'Available'
    }

    # ================================================================
    # DOMAIN
    # ================================================================

    It 'retrieves domain information' {

        $Result = (
            New-TechHubADProvider
        ).GetDomainInformation()

        $Result.Data[0].DNSRoot |
            Should -Be 'example.test'

        $Result.Data[0].NetBIOSName |
            Should -Be 'EXAMPLE'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # FOREST
    # ================================================================

    It 'retrieves forest information' {

        $Result = (
            New-TechHubADProvider
        ).GetForestInformation()

        $Result.Data[0].Name |
            Should -Be 'example.test'

        $Result.Data[0].RootDomain |
            Should -Be 'example.test'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # DOMAIN CONTROLLERS
    # ================================================================

    It 'retrieves domain controllers' {

        $Result = (
            New-TechHubADProvider
        ).GetDomainControllers()

        $Result.Data[0].Name |
            Should -Be 'APP01'

        $Result.Status |
            Should -Be 'Available'
    }

    # ================================================================
    # AD OBJECTS
    # ================================================================

    It 'retrieves and normalizes AD objects' {

        $Result = (
            New-TechHubADProvider
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
    }

    # ================================================================
    # CONSTRAINED DELEGATION - SINGLE VALUE
    # ================================================================

    It 'preserves one constrained delegation target as a string array' {

        $Provider = New-TechHubADProvider

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
    # CONSTRAINED DELEGATION - MULTIPLE VALUES
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
            New-TechHubADProvider
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
    # CONSTRAINED DELEGATION - SCALAR
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
            New-TechHubADProvider
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
    # CONSTRAINED DELEGATION - ABSENT / NULL / EMPTY
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
                New-TechHubADProvider
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
    # REQUESTED PROPERTIES
    # ================================================================

    It 'passes requested properties through to Get-ADObject' {

        $RequestedProperties = @(
            'Name'
            'msDS-AllowedToDelegateTo'
        )

        $Provider = New-TechHubADProvider

        $Provider.GetADObjects(
            '(objectClass=computer)',
            'DC=example,DC=test',
            $RequestedProperties
        ) | Out-Null

        Assert-MockCalled `
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
    # GROUPS
    # ================================================================

    It 'retrieves groups and group members' {

        $Provider = New-TechHubADProvider

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
    # PROVIDER STATUS
    # ================================================================

    It 'reports available provider status after successful operations' {

        $Provider = New-TechHubADProvider

        $Provider.GetDomainInformation() |
            Out-Null

        $Provider.GetForestInformation() |
            Out-Null

        $Provider.GetProviderStatus().Status |
            Should -Be 'Available'
    }

    # ================================================================
    # PARTIAL STATUS
    # ================================================================

    It 'reports partial status when one operation fails after success' {

        $Provider = New-TechHubADProvider

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
    # MODULE UNAVAILABLE
    # ================================================================

    It 'reports NotAvailable when the ActiveDirectory module is unavailable' {

        Mock `
            Test-TechHubADActiveDirectoryAvailability `
            -ModuleName TechHub.ActiveDirectory {
                $false
            }

        $Result = (
            New-TechHubADProvider
        ).GetDomainInformation()

        $Result.Status |
            Should -Be 'NotAvailable'

        $Result.ErrorType |
            Should -Be 'ModuleUnavailable'
    }

    # ================================================================
    # ERROR CLASSIFICATION
    # ================================================================

    It 'classifies access denied, LDAP, not found and server errors' {

        $Provider = New-TechHubADProvider

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
    # SERVER PROPAGATION
    # ================================================================

    It 'propagates Server to read operations' {

        $Provider = New-TechHubADProvider `
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

        Assert-MockCalled `
            Get-ADDomain `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test'
            } `
            -Times 1

        Assert-MockCalled `
            Get-ADObject `
            -ModuleName TechHub.ActiveDirectory `
            -ParameterFilter {
                $Server -eq 'dc01.example.test' -and
                $SearchBase -eq 'DC=example,DC=test'
            } `
            -Times 1
    }

    # ================================================================
    # MISSING PROPERTIES
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
            New-TechHubADProvider
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
    # READ-ONLY SECURITY TEST
    # ================================================================

    It 'is read-only and contains no dynamic or modifying commands' {

        $Source = Get-Content `
            -Path $ProviderPath `
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
            New-TechHubADProvider
        ).GetDomainInformation().IsReadOnly |
            Should -BeTrue
    }
}