$ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\..'

Describe 'TechHubADProvider' {
    BeforeAll {
        Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'TechHub.ActiveDirectory.psm1') -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:Domain = [PSCustomObject]@{ DNSRoot = 'example.test'; NetBIOSName = 'EXAMPLE'; DistinguishedName = 'DC=example,DC=test'; DomainMode = 'Windows2016Domain' }
        $Script:Forest = [PSCustomObject]@{ Name = 'example.test'; ForestMode = 'Windows2016Forest'; RootDomain = 'example.test'; Domains = @('example.test') }
        $Script:Object = [PSCustomObject]@{ Name = 'APP01'; SamAccountName = 'APP01$'; DistinguishedName = 'CN=APP01,DC=example,DC=test'; ObjectGUID = [guid]'11111111-1111-1111-1111-111111111111'; ObjectClass = @('top', 'computer'); ObjectCategory = 'computer'; UserAccountControl = 0; ServicePrincipalName = @('HOST/APP01.example.test'); MemberOf = @('CN=Servers,DC=example,DC=test'); SID = 'S-1-5-21-100-200-300-1101' }
        $Script:Group = [PSCustomObject]@{ Name = 'Domain Admins'; SamAccountName = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=example,DC=test'; ObjectGUID = [guid]'22222222-2222-2222-2222-222222222222'; ObjectClass = @('top', 'group') }
        $Script:Member = [PSCustomObject]@{ Name = 'alice'; SamAccountName = 'alice'; DistinguishedName = 'CN=alice,CN=Users,DC=example,DC=test'; ObjectGUID = [guid]'33333333-3333-3333-3333-333333333333'; ObjectClass = @('top', 'person', 'user'); UserAccountControl = 0; SID = 'S-1-5-21-100-200-300-1102' }
        Mock Get-Module -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ Name = 'ActiveDirectory' } }
        Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory { $Script:Domain }
        Mock Get-ADForest -ModuleName TechHub.ActiveDirectory { $Script:Forest }
        Mock Get-ADDomainController -ModuleName TechHub.ActiveDirectory { @($Script:Object) }
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { @($Script:Object) }
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { @($Script:Group) }
        Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory { @($Script:Member) }
    }

    It 'creates a provider without contacting Active Directory' {
        $Provider = New-TechHubADProvider
        $Provider.GetType().Name | Should -Be 'TechHubADProvider'
        $Provider.Server | Should -BeNullOrEmpty
        Assert-MockCalled Get-ADObject -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'reports module availability' {
        $Provider = New-TechHubADProvider
        $Provider.GetDomainInformation().Status | Should -Be 'Available'
        Assert-MockCalled Get-Module -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Name -eq 'ActiveDirectory' } -Times 1
    }

    It 'retrieves domain information' {
        $Result = (New-TechHubADProvider).GetDomainInformation()
        $Result.Data[0].DNSRoot | Should -Be 'example.test'
        $Result.Operation | Should -Be 'GetDomainInformation'
    }

    It 'retrieves forest information' {
        $Result = (New-TechHubADProvider).GetForestInformation()
        $Result.Data[0].Name | Should -Be 'example.test'
    }

    It 'retrieves domain controllers' {
        $Result = (New-TechHubADProvider).GetDomainControllers()
        $Result.Data[0].Name | Should -Be 'APP01'
    }

    It 'retrieves and normalizes AD objects' {
        $Result = (New-TechHubADProvider).GetADObjects('(&(objectClass=computer))', $null, @('Name'))
        $Object = $Result.Data[0]
        $Object.Name | Should -Be 'APP01'
        $Object.ObjectGUID | Should -Be ([guid]'11111111-1111-1111-1111-111111111111')
        $Object.Enabled | Should -BeTrue
        $Object.ServicePrincipalName | Should -Contain 'HOST/APP01.example.test'
    }

    It 'retrieves groups and group members' {
        $Provider = New-TechHubADProvider
        $GroupResult = $Provider.GetGroups($null, $null)
        $MemberResult = $Provider.GetGroupMembers('CN=Domain Admins,CN=Users,DC=example,DC=test')
        $GroupResult.Data[0].Name | Should -Be 'Domain Admins'
        $MemberResult.Data[0].SamAccountName | Should -Be 'alice'
    }

    It 'reports available provider status after successful operations' {
        $Provider = New-TechHubADProvider
        $Provider.GetDomainInformation() | Out-Null
        $Provider.GetForestInformation() | Out-Null
        $Provider.GetProviderStatus().Status | Should -Be 'Available'
    }

    It 'reports partial status when one operation fails after success' {
        $Provider = New-TechHubADProvider
        $Provider.GetDomainInformation() | Out-Null
        Mock Get-ADDomainController -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('server unavailable') }
        $Provider.GetDomainControllers().Status | Should -Be 'Error'
        $Provider.GetProviderStatus().Status | Should -Be 'Partial'
    }

    It 'reports NotAvailable when the ActiveDirectory module is unavailable' {
        Mock Get-Module -ModuleName TechHub.ActiveDirectory { $null }
        $Result = (New-TechHubADProvider).GetDomainInformation()
        $Result.Status | Should -Be 'NotAvailable'
        $Result.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'classifies access denied, LDAP, not found and server errors' {
        $Provider = New-TechHubADProvider
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('Access denied') }
        $Provider.GetADObjects('(objectClass=*)', $null, @('Name')).ErrorType | Should -Be 'AccessDenied'
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('LDAP error') }
        $Provider.GetADObjects('(objectClass=*)', $null, @('Name')).ErrorType | Should -Be 'LdapError'
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('object not found') }
        $Provider.GetGroups($null, $null).ErrorType | Should -Be 'ObjectNotFound'
        Mock Get-ADForest -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('domain controller unreachable') }
        $Provider.GetForestInformation().ErrorType | Should -Be 'ServerUnavailable'
    }

    It 'propagates Server to read operations' {
        $Provider = New-TechHubADProvider -Server 'dc01.example.test'
        $Provider.GetDomainInformation() | Out-Null
        $Provider.GetADObjects('(objectClass=*)', 'DC=example,DC=test', @('Name')) | Out-Null
        Assert-MockCalled Get-ADDomain -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Server -eq 'dc01.example.test' } -Times 1
        Assert-MockCalled Get-ADObject -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Server -eq 'dc01.example.test' -and $SearchBase -eq 'DC=example,DC=test' } -Times 1
    }

    It 'returns null for missing properties without throwing' {
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ Name = 'MINIMAL' } }
        $Object = (New-TechHubADProvider).GetADObjects('(objectClass=*)', $null, @('Name')).Data[0]
        $Object.Name | Should -Be 'MINIMAL'
        $Object.SamAccountName | Should -BeNullOrEmpty
        $Object.ServicePrincipalName.Count | Should -Be 0
    }

    It 'is read-only and contains no dynamic or modifying commands' {
        $Source = Get-Content -Path (Join-Path $ModuleRoot 'Providers\ActiveDirectory\TechHubADProvider.ps1') -Raw
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process')
        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
        (New-TechHubADProvider).GetDomainInformation().IsReadOnly | Should -BeTrue
    }
}
