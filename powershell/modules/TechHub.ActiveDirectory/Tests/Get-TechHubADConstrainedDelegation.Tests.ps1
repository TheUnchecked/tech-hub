$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..'

Describe 'Get-TechHubADConstrainedDelegation' {
    BeforeAll {
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $User = [PSCustomObject]@{
            Name                       = 'svc-web'
            DistinguishedName          = 'CN=svc-web,OU=Service Accounts,DC=example,DC=test'
            ObjectGUID                 = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass                = @('top', 'person', 'user')
            ObjectCategory             = 'CN=Person,CN=Schema,CN=Configuration,DC=example,DC=test'
            SamAccountName             = 'svc-web'
            UserAccountControl         = 0
            Enabled                    = $true
            ServicePrincipalName       = @('HTTP/web.example.test')
            'msDS-AllowedToDelegateTo' = @('HTTP/api.example.test')
        }
        $Computer = [PSCustomObject]@{
            Name                       = 'WEB01'
            DistinguishedName          = 'CN=WEB01,OU=Servers,DC=example,DC=test'
            ObjectGUID                 = [guid]'44444444-4444-4444-4444-444444444444'
            ObjectClass                = @('top', 'person', 'computer')
            ObjectCategory             = 'CN=Computer,CN=Schema,CN=Configuration,DC=example,DC=test'
            SamAccountName             = 'WEB01$'
            UserAccountControl         = 0
            Enabled                    = $true
            ServicePrincipalName       = @('HOST/WEB01.example.test')
            'msDS-AllowedToDelegateTo' = @('HTTP/api.example.test')
        }
        Mock -CommandName Get-ADDomain -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ DNSRoot = 'example.test' }
        }
        Mock -CommandName Get-ADForest -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Name = 'example.test' }
        }
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            @($User, $Computer)
        }
    }

    It 'returns a user finding with one destination' {
        $Result = @(Get-TechHubADConstrainedDelegation | Where-Object ObjectType -eq 'User')[0]
        $Result.ObjectType | Should -Be 'User'
        $Result.Evidence.AllowedToDelegateTo | Should -Contain 'HTTP/api.example.test'
        $Result.Severity | Should -Be 'Low'
    }

    It 'returns a computer finding with one destination' {
        $Result = @(Get-TechHubADConstrainedDelegation | Where-Object ObjectType -eq 'Computer')[0]
        $Result.ObjectType | Should -Be 'Computer'
        $Result.Evidence.AccountEnabled | Should -BeTrue
    }

    It 'classifies multiple destinations as medium' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            $User.'msDS-AllowedToDelegateTo' = @('HTTP/api.example.test', 'LDAP/dc.example.test')
            $User
        }
        $Result = @(Get-TechHubADConstrainedDelegation)[0]
        $Result.Evidence.AllowedToDelegateTo.Count | Should -Be 2
        $Result.Severity | Should -Be 'Medium'
    }

    It 'classifies a configured critical destination as high' {
        $Result = @(Get-TechHubADConstrainedDelegation -CriticalServicePatterns 'HTTP/*')[0]
        $Result.Severity | Should -Be 'High'
        $Result.Evidence.CriticalMatches | Should -Contain 'HTTP/api.example.test'
    }

    It 'classifies a disabled account as informational' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            $User.UserAccountControl = 2
            $User.Enabled = $false
            $User
        }
        $Result = @(Get-TechHubADConstrainedDelegation)[0]
        $Result.Severity | Should -Be 'Informational'
        $Result.Status | Should -Be 'Finding'
    }

    It 'returns no finding when the delegation attribute is absent' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Name = 'NO-DELEGATION'; UserAccountControl = 0 }
        }
        @(Get-TechHubADConstrainedDelegation).Count | Should -Be 0
    }

    It 'handles missing SPNs' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            $User.PSObject.Properties.Remove('ServicePrincipalName')
            $User
        }
        $Result = @(Get-TechHubADConstrainedDelegation)[0]
        $Result.Evidence.ServicePrincipalNames.Count | Should -Be 0
    }

    It 'handles incomplete properties with medium confidence' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Name                       = 'INCOMPLETE'
                ObjectClass                = @('top', 'person', 'user')
                UserAccountControl         = 0
                'msDS-AllowedToDelegateTo' = 'HTTP/api.example.test'
            }
        }
        $Result = @(Get-TechHubADConstrainedDelegation)[0]
        $Result.Confidence | Should -Be 'Medium'
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'handles empty results' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith { @() }
        @(Get-TechHubADConstrainedDelegation).Count | Should -Be 0
    }

    It 'handles LDAP errors' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            throw [System.Exception]::new('Synthetic LDAP failure')
        }
        @(Get-TechHubADConstrainedDelegation -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'returns the complete finding contract and read-only marker' {
        $Result = @(Get-TechHubADConstrainedDelegation)[0]
        $RequiredProperties = @('AssessmentId', 'CheckId', 'CheckName', 'FindingId', 'Title', 'Description', 'Category', 'Severity', 'Confidence', 'Status', 'AffectedObject', 'ObjectType', 'DistinguishedName', 'SamAccountName', 'ObjectGuid', 'Evidence', 'Risk', 'Recommendation', 'References', 'CollectedAt', 'Domain', 'Forest', 'DomainController', 'IsReadOnly')
        foreach ($Property in $RequiredProperties) {
            $Result.PSObject.Properties.Name | Should -Contain $Property
        }
        $Result.IsReadOnly | Should -BeTrue
        $Result.Evidence.PSObject.Properties.Name | Should -Contain 'AllowedToDelegateTo'
        $Result.Evidence.PSObject.Properties.Name | Should -Contain 'ServicePrincipalNames'
        $Result.Evidence.PSObject.Properties.Name | Should -Contain 'AccountEnabled'
        $Result.Evidence.PSObject.Properties.Name | Should -Contain 'UserAccountControl'
    }

    It 'supports verbose output' {
        { Get-TechHubADConstrainedDelegation -Verbose 4>&1 | Out-Null } | Should -Not -Throw
    }

    It 'passes server and search base to the read-only query' {
        Get-TechHubADConstrainedDelegation -Server 'dc01.example.test' -SearchBase 'OU=Servers,DC=example,DC=test' | Out-Null
        Assert-MockCalled -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -Times 1 -ParameterFilter {
            $Server -eq 'dc01.example.test' -and $SearchBase -eq 'OU=Servers,DC=example,DC=test'
        }
    }

    It 'contains no AD modification cmdlets' {
        $Source = Get-Content -Path (Join-Path $PSScriptRoot '..\Public\Get-TechHubADConstrainedDelegation.ps1') -Raw
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
    }
}
