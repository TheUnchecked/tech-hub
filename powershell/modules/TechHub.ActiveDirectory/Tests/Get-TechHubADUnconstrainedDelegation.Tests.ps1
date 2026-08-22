$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..'

Describe 'Get-TechHubADUnconstrainedDelegation' {
    BeforeAll {
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $EnabledComputer = [PSCustomObject]@{
            Name               = 'APP01'
            DistinguishedName  = 'CN=APP01,OU=Servers,DC=example,DC=test'
            ObjectGUID         = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass        = @('top', 'person', 'computer')
            ObjectCategory     = 'CN=Computer,CN=Schema,CN=Configuration,DC=example,DC=test'
            SamAccountName     = 'APP01$'
            UserAccountControl = 0x80000
            ServicePrincipalName = @('HOST/APP01.example.test')
        }
        $DisabledUser = [PSCustomObject]@{
            Name               = 'svc-legacy'
            DistinguishedName  = 'CN=svc-legacy,OU=Service Accounts,DC=example,DC=test'
            ObjectGUID         = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass        = @('top', 'person', 'user')
            ObjectCategory     = 'CN=Person,CN=Schema,CN=Configuration,DC=example,DC=test'
            SamAccountName     = 'svc-legacy'
            UserAccountControl = 0x80002
            ServicePrincipalName = @()
        }

        Mock -CommandName Get-ADDomain -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ DNSRoot = 'example.test' }
        }
        Mock -CommandName Get-ADForest -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Name = 'example.test' }
        }
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            @($EnabledComputer, $DisabledUser)
        }
    }

    It 'returns findings for enabled computers and disabled users' {
        $Results = @(Get-TechHubADUnconstrainedDelegation)

        $Results.Count | Should -Be 2
        ($Results | Where-Object ObjectType -eq 'Computer').Severity | Should -Be 'High'
        ($Results | Where-Object ObjectType -eq 'User').Severity | Should -Be 'Medium'
        ($Results | Where-Object ObjectType -eq 'User').AffectedObject.Enabled | Should -BeFalse
    }

    It 'identifies the TRUSTED_FOR_DELEGATION flag and includes SPNs' {
        $Result = @(Get-TechHubADUnconstrainedDelegation)[0]

        $Result.Evidence.TrustedForDelegation | Should -BeTrue
        $Result.Evidence.ServicePrincipalNames | Should -Contain 'HOST/APP01.example.test'
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'distinguishes computer and user accounts' {
        $Results = @(Get-TechHubADUnconstrainedDelegation)

        ($Results | Where-Object SamAccountName -eq 'APP01$').ObjectType | Should -Be 'Computer'
        ($Results | Where-Object SamAccountName -eq 'svc-legacy').ObjectType | Should -Be 'User'
    }

    It 'returns no output when no matching objects are found' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        @(Get-TechHubADUnconstrainedDelegation).Count | Should -Be 0
    }

    It 'handles incomplete objects with medium confidence' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Name               = 'INCOMPLETE'
                ObjectClass        = @('top', 'person', 'computer')
                UserAccountControl = 0x80000
            }
        }

        $Result = @(Get-TechHubADUnconstrainedDelegation)[0]

        $Result.Confidence | Should -Be 'Medium'
        $Result.ObjectType | Should -Be 'Computer'
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'handles LDAP errors without producing a string result' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            throw [System.Exception]::new('Synthetic LDAP failure')
        }

        $Results = @(Get-TechHubADUnconstrainedDelegation -ErrorAction SilentlyContinue)

        $Results.Count | Should -Be 0
    }

    It 'passes server and search base to the read-only query' {
        Get-TechHubADUnconstrainedDelegation -Server 'dc01.example.test' -SearchBase 'OU=Servers,DC=example,DC=test' | Out-Null

        Assert-MockCalled -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -Times 1 -ParameterFilter {
            $Server -eq 'dc01.example.test' -and
            $SearchBase -eq 'OU=Servers,DC=example,DC=test'
        }
    }

    It 'returns the complete finding contract' {
        $Result = @(Get-TechHubADUnconstrainedDelegation)[0]
        $RequiredProperties = @(
            'AssessmentId', 'CheckId', 'CheckName', 'FindingId', 'Title',
            'Description', 'Category', 'Severity', 'Confidence', 'Status',
            'AffectedObject', 'ObjectType', 'DistinguishedName',
            'SamAccountName', 'ObjectGuid', 'Evidence', 'Risk',
            'Recommendation', 'References', 'CollectedAt', 'Domain',
            'Forest', 'DomainController', 'IsReadOnly'
        )

        foreach ($Property in $RequiredProperties) {
            $Result.PSObject.Properties.Name | Should -Contain $Property
        }
    }
}
