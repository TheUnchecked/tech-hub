$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..'

function New-TestADProviderResult {
    param (
        [string]$Status = 'Available',
        [object[]]$Data = @(),
        [string]$ErrorType,
        [string]$ErrorMessage
    )

    [PSCustomObject][ordered]@{
        Provider = 'TechHubADProvider'
        Operation = 'GetADObjects'
        Status = $Status
        Data = @($Data)
        ErrorType = $ErrorType
        ErrorMessage = $ErrorMessage
        Server = $null
        IsReadOnly = $true
    }
}

function New-TestADProvider {
    param (
        [string]$ObjectStatus = 'Available',
        [object[]]$Objects = @(),
        [string]$ErrorType,
        [string]$ErrorMessage
    )

    $Provider = [PSCustomObject]@{
        Server = $null
        DomainResult = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ DNSRoot = 'example.test' }) }
        ForestResult = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ Name = 'example.test' }) }
        ObjectResult = New-TestADProviderResult -Status $ObjectStatus -Data $Objects -ErrorType $ErrorType -ErrorMessage $ErrorMessage
        LastLdapFilter = $null
        LastSearchBase = $null
        LastProperties = $null
    }
    Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value { $this.DomainResult }
    Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value { $this.ForestResult }
    Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetADObjects -Value {
        param($LdapFilter, $SearchBase, $Properties)
        $this.LastLdapFilter = $LdapFilter
        $this.LastSearchBase = $SearchBase
        $this.LastProperties = $Properties
        $this.ObjectResult
    }
    $Provider
}

Describe 'Get-TechHubADUnconstrainedDelegation provider migration' {
    BeforeAll {
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:Computer = [PSCustomObject]@{
            Name = 'APP01'
            DistinguishedName = 'CN=APP01,OU=Servers,DC=example,DC=test'
            ObjectGUID = [guid]'11111111-1111-1111-1111-111111111111'
            ObjectClass = @('top', 'person', 'computer')
            ObjectCategory = 'computer'
            SamAccountName = 'APP01$'
            UserAccountControl = 0x80000
            Enabled = $true
            ServicePrincipalName = @('HOST/APP01.example.test')
        }
        $Script:User = [PSCustomObject]@{
            Name = 'svc-legacy'
            DistinguishedName = 'CN=svc-legacy,OU=Service Accounts,DC=example,DC=test'
            ObjectGUID = [guid]'22222222-2222-2222-2222-222222222222'
            ObjectClass = @('top', 'person', 'user')
            ObjectCategory = 'person'
            SamAccountName = 'svc-legacy'
            UserAccountControl = 0x80002
            Enabled = $false
            ServicePrincipalName = @()
        }
        $Script:Provider = New-TestADProvider -Objects @($Script:Computer, $Script:User)
    }

    It 'processes a computer from a synthetic provider' {
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Script:Provider | Where-Object ObjectType -eq 'Computer')[0]
        $Result.ObjectType | Should -Be 'Computer'
        $Result.Evidence.TrustedForDelegation | Should -BeTrue
        $Result.Severity | Should -Be 'High'
    }

    It 'processes a user from a synthetic provider' {
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Script:Provider | Where-Object ObjectType -eq 'User')[0]
        $Result.ObjectType | Should -Be 'User'
        $Result.Severity | Should -Be 'Medium'
        $Result.Evidence.AccountEnabled | Should -BeFalse
    }

    It 'preserves the flag, SPN and Finding Contract v1' {
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Script:Provider)[0]
        $Result.CheckId | Should -Be 'AD-UNCONSTRAINED-DELEGATION'
        $Result.CheckName | Should -Be 'Unconstrained Delegation'
        $Result.Category | Should -Be 'Delegation'
        $Result.Evidence.UserAccountControl | Should -Be 0x80000
        $Result.Evidence.ServicePrincipalNames | Should -Contain 'HOST/APP01.example.test'
        $Result.IsReadOnly | Should -BeTrue
        @('AssessmentId','CheckId','CheckName','FindingId','Title','Description','Category','Severity','Confidence','Status','AffectedObject','ObjectType','DistinguishedName','SamAccountName','ObjectGuid','Evidence','Risk','Recommendation','References','CollectedAt','Domain','Forest','DomainController','IsReadOnly') | ForEach-Object { $Result.PSObject.Properties.Name | Should -Contain $_ }
    }

    It 'returns no finding for no matching objects' {
        $Provider = New-TestADProvider -Objects @()
        @(Get-TechHubADUnconstrainedDelegation -Provider $Provider).Count | Should -Be 0
    }

    It 'processes sufficient data from a Partial provider result' {
        $Provider = New-TestADProvider -ObjectStatus 'Partial' -Objects @($Script:Computer)
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Provider)[0]
        $Result.Evidence.ProviderStatus | Should -Be 'Partial'
        $Result.Evidence.TrustedForDelegation | Should -BeTrue
    }

    It 'returns a structured contract result for NotAvailable data' {
        $Provider = New-TestADProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable provider'
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Provider)[0]
        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'returns a structured contract result for provider Error' {
        $Provider = New-TestADProvider -ObjectStatus 'Error' -ErrorType 'LdapError' -ErrorMessage 'Synthetic LDAP error'
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Provider)[0]
        $Result.Status | Should -Be 'Error'
        $Result.Evidence.ErrorType | Should -Be 'LdapError'
    }

    It 'handles incomplete objects and missing SPNs' {
        $Incomplete = [PSCustomObject]@{ Name = 'INCOMPLETE'; ObjectClass = @('computer'); UserAccountControl = 0x80000 }
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider (New-TestADProvider -Objects @($Incomplete)))[0]
        $Result.Confidence | Should -Be 'Medium'
        $Result.Evidence.ServicePrincipalNames.Count | Should -Be 0
    }

    It 'passes SearchBase to the provider and Server when constructing the provider' {
        Mock -CommandName New-TechHubADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            $Provider = New-TestADProvider -Objects @($Script:Computer)
            $Provider.Server = $Server
            $Script:ConstructedProvider = $Provider
        }
        Get-TechHubADUnconstrainedDelegation -Server 'dc01.example.test' -SearchBase 'OU=Servers,DC=example,DC=test' | Out-Null
        Assert-MockCalled -CommandName New-TechHubADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Server -eq 'dc01.example.test' } -Times 1
        $Script:ConstructedProvider.LastSearchBase | Should -Be 'OU=Servers,DC=example,DC=test'
    }

    It 'works without an Active Directory cmdlet available' {
        Get-Command Get-ADObject -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $Result = @(Get-TechHubADUnconstrainedDelegation -Provider $Script:Provider)[0]
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'contains no direct AD cmdlets, modifying cmdlets or dynamic execution' {
        $Source = Get-Content -Path (Join-Path $PSScriptRoot '..\Public\Get-TechHubADUnconstrainedDelegation.ps1') -Raw
        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process')
        foreach ($Marker in $DynamicMarkers) { $Source -match [regex]::Escape($Marker) | Should -BeFalse }
    }
}
