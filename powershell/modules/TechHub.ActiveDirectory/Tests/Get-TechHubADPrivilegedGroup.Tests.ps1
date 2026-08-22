$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..'

function New-TestGroupMember {
    param([string]$Name, [string[]]$ObjectClass, [string]$DistinguishedName, [string]$SamAccountName)
    [PSCustomObject]@{ Name = $Name; ObjectClass = $ObjectClass; ObjectGUID = [guid]::NewGuid(); DistinguishedName = $DistinguishedName; SamAccountName = $SamAccountName; SID = 'S-1-5-21-100-200-300-1101' }
}

Describe 'Get-TechHubADPrivilegedGroup' {
    BeforeAll { Import-Module -Name $ModulePath -Force -ErrorAction Stop }
    AfterAll { Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue }
    BeforeEach {
        $Script:Group = [PSCustomObject]@{ Name = 'Domain Admins'; SamAccountName = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=example,DC=test'; ObjectGUID = [guid]'77777777-7777-7777-7777-777777777777'; ObjectClass = @('top', 'group') }
        $Script:User = New-TestGroupMember 'alice' @('top', 'person', 'user') 'CN=alice,CN=Users,DC=example,DC=test' 'alice'
        $Script:Computer = New-TestGroupMember 'WEB01$' @('top', 'person', 'computer') 'CN=WEB01,OU=Servers,DC=example,DC=test' 'WEB01$'
        $Script:Details = @{
            'CN=alice,CN=Users,DC=example,DC=test' = [PSCustomObject]@{ Name='alice'; SamAccountName='alice'; ObjectClass=@('user'); ObjectGUID=$Script:User.ObjectGUID; DistinguishedName=$Script:User.DistinguishedName; Enabled=$true; adminCount=0; PasswordNeverExpires=$false; SID='S-1-5-21-100-200-300-1101' }
            'CN=WEB01,OU=Servers,DC=example,DC=test' = [PSCustomObject]@{ Name='WEB01$'; SamAccountName='WEB01$'; ObjectClass=@('computer'); ObjectGUID=$Script:Computer.ObjectGUID; DistinguishedName=$Script:Computer.DistinguishedName; Enabled=$true; adminCount=0; PasswordNeverExpires=$false; SID='S-1-5-21-100-200-300-1102' }
        }
        Mock Get-ADDomain -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ DNSRoot='example.test' } }
        Mock Get-ADForest -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ Name='example.test' } }
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { @($Script:Group) }
        Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory { @($Script:User) }
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { if ($Script:Details.ContainsKey($Identity)) { $Script:Details[$Identity] } }
    }

    It 'finds a privileged group and normalizes a direct user member' {
        $Result = @(Get-TechHubADPrivilegedGroup)[0]
        $Result.Evidence.MemberObjectType | Should -Be 'User'
        $Result.Evidence.MembershipType | Should -Be 'Direct'
    }
    It 'handles a computer member' { $Script:User = $Script:Computer; (Get-TechHubADPrivilegedGroup | Select-Object -First 1).Evidence.MemberObjectType | Should -Be 'Computer' }
    It 'handles nested groups and membership paths' {
        $Nested = New-TestGroupMember 'Tier2-Admins' @('group') 'CN=Tier2-Admins,OU=Groups,DC=example,DC=test' 'Tier2-Admins'
        $Script:User = $Nested
        Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory { if ($Identity -eq $Script:Group.DistinguishedName) { @($Nested) } else { @($Script:Computer) } }
        $Results = @(Get-TechHubADPrivilegedGroup)
        $Results.Count | Should -Be 2
        ($Results | Where-Object { $_.Evidence.MembershipType -eq 'Indirect' }).Evidence.MembershipPath.Count | Should -BeGreaterThan 0
    }
    It 'prevents cycles in nested groups' {
        $A = New-TestGroupMember 'GroupA' @('group') 'CN=GroupA,DC=example,DC=test' 'GroupA'
        Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory { if ($Identity -eq $Script:Group.DistinguishedName) { @($A) } else { @($A) } }
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ Name='GroupA'; ObjectClass=@('group'); DistinguishedName='CN=GroupA,DC=example,DC=test'; Enabled=$true } }
        @(Get-TechHubADPrivilegedGroup).Count | Should -Be 1
    }
    It 'handles unresolved members, disabled accounts, adminCount and password expiry' {
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { [PSCustomObject]@{ Name='alice'; SamAccountName='alice'; ObjectClass=@('user'); DistinguishedName=$Script:User.DistinguishedName; Enabled=$false; adminCount=1; PasswordNeverExpires=$true; SID=$Script:User.SID } }
        $Result = @(Get-TechHubADPrivilegedGroup -IncludeDisabled)[0]
        $Result.Evidence.Enabled | Should -BeFalse
        $Result.Evidence.AdminCount | Should -Be 1
        $Result.Evidence.PasswordNeverExpires | Should -BeTrue
        $Result.Severity | Should -Be 'High'
        $Result.IsReadOnly | Should -BeTrue
    }
    It 'handles an unresolved member without failing the assessment' {
        Mock Get-ADObject -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('SID not resolved') }
        $Result = @(Get-TechHubADPrivilegedGroup -IncludeDisabled)[0]
        $Result.Confidence | Should -Be 'Medium'
        $Result.Evidence.MemberName | Should -Be 'alice'
    }
    It 'classifies approved, excluded and service account patterns' {
        (Get-TechHubADPrivilegedGroup -ApprovedMemberPatterns 'alice').Severity | Should -Be 'Informational'
        (Get-TechHubADPrivilegedGroup -ExcludedMemberPatterns 'alice').Status | Should -Be 'NotApplicable'
        (Get-TechHubADPrivilegedGroup -ServiceAccountPatterns 'alice').Evidence.IsServiceAccount | Should -BeTrue
    }
    It 'handles missing groups and empty groups' {
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { @() }
        @(Get-TechHubADPrivilegedGroup).Count | Should -Be 0
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { @($Script:Group) }
        Mock Get-ADGroupMember -ModuleName TechHub.ActiveDirectory { @() }
        (Get-TechHubADPrivilegedGroup | Select-Object -First 1).Severity | Should -Be 'Informational'
    }
    It 'handles empty results and LDAP/access errors' {
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { @() }
        @(Get-TechHubADPrivilegedGroup).Count | Should -Be 0
        Mock Get-ADGroup -ModuleName TechHub.ActiveDirectory { throw [System.Exception]::new('Access denied') }
        @(Get-TechHubADPrivilegedGroup -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'supports verbose, server, search base and group extension' {
        { Get-TechHubADPrivilegedGroup -Verbose -Server 'dc01.example.test' -SearchBase 'OU=Groups,DC=example,DC=test' -GroupPatterns 'Custom-*' | Out-Null } | Should -Not -Throw
        Assert-MockCalled Get-ADGroup -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Server -eq 'dc01.example.test' -and $SearchBase -eq 'OU=Groups,DC=example,DC=test' } -Times 1
    }
    It 'returns the complete contract and contains no AD modification cmdlets' {
        $Result = @(Get-TechHubADPrivilegedGroup)[0]
        @('AssessmentId','CheckId','CheckName','FindingId','Title','Description','Category','Severity','Confidence','Status','AffectedObject','ObjectType','DistinguishedName','SamAccountName','ObjectGuid','Evidence','Risk','Recommendation','References','CollectedAt','Domain','Forest','DomainController','IsReadOnly') | ForEach-Object { $Result.PSObject.Properties.Name | Should -Contain $_ }
        $Result.Category | Should -Be 'PrivilegedAccess'
        $Source = Get-Content (Join-Path $PSScriptRoot '..\Public\Get-TechHubADPrivilegedGroup.ps1') -Raw
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
    }
}
