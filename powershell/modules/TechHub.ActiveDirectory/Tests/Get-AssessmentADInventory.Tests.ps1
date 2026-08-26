#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADInventory provider migration' {

    BeforeAll {

        $ModulePath = Join-Path $PSScriptRoot '..'

        Import-Module $ModulePath -Force -ErrorAction Stop

        $Script:User = [PSCustomObject][ordered]@{
            Name               = 'Alice'
            DistinguishedName  = 'CN=Alice,OU=Users,DC=example,DC=test'
            SamAccountName     = 'alice'
            ObjectClass        = 'user'
            canonicalName      = 'example.test/Users/Alice'
            Description        = 'Synthetic test object'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = 133700000000000000
            lastLogonTimestamp  = 133700000000000000
            groupCategory      = $null
            groupScope         = $null
        }

        $Script:Computer = [PSCustomObject][ordered]@{
            Name               = 'WEB01'
            DistinguishedName  = 'CN=WEB01,OU=Servers,DC=example,DC=test'
            SamAccountName     = 'WEB01$'
            ObjectClass        = 'computer'
            canonicalName      = 'example.test/Servers/WEB01'
            Description        = 'Synthetic computer'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = 133700000000000000
            lastLogonTimestamp  = 133700000000000000
            groupCategory      = $null
            groupScope         = $null
        }

        $Script:Group = [PSCustomObject][ordered]@{
            Name               = 'Domain Admins'
            DistinguishedName  = 'CN=Domain Admins,CN=Users,DC=example,DC=test'
            SamAccountName     = 'Domain Admins'
            ObjectClass        = 'group'
            canonicalName      = 'example.test/Users/Domain Admins'
            Description        = 'Synthetic group'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = $null
            lastLogonTimestamp  = $null
            groupCategory      = 'Security'
            groupScope         = 'Global'
        }

        $Script:OU = [PSCustomObject][ordered]@{
            Name               = 'Servers'
            DistinguishedName  = 'OU=Servers,DC=example,DC=test'
            SamAccountName     = $null
            ObjectClass        = 'organizationalUnit'
            canonicalName      = 'example.test/Servers'
            Description        = 'Synthetic OU'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = $null
            lastLogonTimestamp  = $null
            groupCategory      = $null
            groupScope         = $null
        }

        $Script:MSA = [PSCustomObject][ordered]@{
            Name               = 'svc-web'
            DistinguishedName  = 'CN=svc-web,CN=Managed Service Accounts,DC=example,DC=test'
            SamAccountName     = 'svc-web$'
            ObjectClass        = 'msDS-ManagedServiceAccount'
            canonicalName      = 'example.test/Managed Service Accounts/svc-web'
            Description        = 'Synthetic MSA'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = $null
            lastLogonTimestamp  = $null
            groupCategory      = $null
            groupScope         = $null
        }

        $Script:gMSA = [PSCustomObject][ordered]@{
            Name               = 'gsvc-web'
            DistinguishedName  = 'CN=gsvc-web,CN=Managed Service Accounts,DC=example,DC=test'
            SamAccountName     = 'gsvc-web$'
            ObjectClass        = 'msDS-GroupManagedServiceAccount'
            canonicalName      = 'example.test/Managed Service Accounts/gsvc-web'
            Description        = 'Synthetic gMSA'
            Enabled            = $true
            whenCreated        = [datetime]'2026-01-01T10:00:00Z'
            whenChanged        = [datetime]'2026-01-02T10:00:00Z'
            pwdLastSet         = $null
            lastLogonTimestamp  = $null
            groupCategory      = $null
            groupScope         = $null
        }
    }

    AfterAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'returns users' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(&(objectCategory=person)(objectClass=user))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:User)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 1
        $result[0].ObjectType | Should -Be 'User'
        $result[0].ObjectName | Should -Be 'alice'
    }

    It 'returns computers' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(&(objectCategory=computer))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:Computer)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 1
        $result[0].ObjectType | Should -Be 'Computer'
        $result[0].ObjectName | Should -Be 'WEB01$'
    }

    It 'returns groups' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(&(objectCategory=group))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:Group)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 1
        $result[0].ObjectType | Should -Be 'Group'
        $result[0].ObjectName | Should -Be 'Domain Admins'
    }

    It 'returns organizational units' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(objectCategory=organizationalUnit)') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:OU)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 1
        $result[0].ObjectType | Should -Be 'Organizational Unit'
        $result[0].ObjectName | Should -Be 'Servers'
    }

    It 'returns MSA and gMSA objects' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(&(objectClass=msDS-ManagedServiceAccount))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:MSA)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                if ($Filter -eq '(&(objectClass=msDS-GroupManagedServiceAccount))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:gMSA)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        @(
            $result | Where-Object ObjectType -eq 'MSA'
        ).Count | Should -Be 1

        @(
            $result | Where-Object ObjectType -eq 'gMSA'
        ).Count | Should -Be 1
    }

    It 'returns empty collection for empty provider data' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 0
    }

    It 'passes SearchBase to provider' {

        $provider = [PSCustomObject]@{
            Server      = 'DC01.example.test'
            SearchBases = [System.Collections.Generic.List[string]]::new()
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                $this.SearchBases.Add($SearchBase)

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        Get-AssessmentADInventory `
            -Provider $provider `
            -SearchBase 'OU=Servers,DC=example,DC=test' |
            Out-Null

        @(
            $provider.SearchBases |
                Where-Object {
                    $_ -eq 'OU=Servers,DC=example,DC=test'
                }
        ).Count | Should -BeGreaterThan 0
    }

    It 'returns structured inventory contract fields' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                if ($Filter -eq '(&(objectCategory=person)(objectClass=user))') {
                    return [PSCustomObject]@{
                        Provider     = 'TechHubADProvider'
                        Operation    = 'GetADObjects'
                        Status       = 'Available'
                        Data         = @($Script:User)
                        ErrorType    = $null
                        ErrorMessage = $null
                        Server       = 'DC01.example.test'
                        IsReadOnly   = $true
                    }
                }

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        $result = @(Get-AssessmentADInventory -Provider $provider)

        $result.Count | Should -Be 1

        $result[0].PSObject.Properties.Name |
            Should -Contain 'ObjectName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'ObjectType'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'DistinguishedName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'CreationTimestamp'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'UpdateTimestamp'

        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'works only with synthetic provider data' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @($Script:User)
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        {
            Get-AssessmentADInventory -Provider $provider |
                Out-Null
        } | Should -Not -Throw
    }

    It 'does not execute modification operations' {

        $provider = [PSCustomObject]@{
            Server = 'DC01.example.test'
        }

        Add-Member `
            -InputObject $provider `
            -MemberType ScriptMethod `
            -Name GetADObjects `
            -Value {
                param($Filter, $SearchBase, $Properties)

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetADObjects'
                    Status       = 'Available'
                    Data         = @()
                    ErrorType    = $null
                    ErrorMessage = $null
                    Server       = 'DC01.example.test'
                    IsReadOnly   = $true
                }
            }

        {
            Get-AssessmentADInventory -Provider $provider |
                Out-Null
        } | Should -Not -Throw
    }
}