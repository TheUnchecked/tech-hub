$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..'

Describe 'ConvertFrom-TechHubADRBCDDescriptor' {
    BeforeAll {
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'normalizes a synthetic security descriptor' {
        $Rule = [PSCustomObject]@{
            IdentityReference  = 'S-1-5-21-100-200-300-1101'
            AccessControlType  = 'Allow'
            AccessMask         = 983551
            ObjectType         = [guid]::Empty
        }
        $Descriptor = [PSCustomObject]@{ AccessRules = @($Rule) }
        Add-Member -InputObject $Descriptor -MemberType ScriptMethod -Name GetAccessRules -Value { $this.AccessRules }

        InModuleScope TechHub.ActiveDirectory -Parameters @{ TestDescriptor = $Descriptor } {
            param($TestDescriptor)
            $Result = @(ConvertFrom-TechHubADRBCDDescriptor -Descriptor $TestDescriptor)
            $Result.Count | Should -Be 1
            $Result.SID | Should -Be 'S-1-5-21-100-200-300-1101'
            $Result.AccessType | Should -Be 'Allow'
            $Result.AccessMask | Should -Be 983551
            $Result.ObjectType | Should -Be ([guid]::Empty)
        }
    }
}

Describe 'Get-TechHubADRBCD' {
    BeforeAll {
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:TargetSid = 'S-1-5-21-100-200-300-1101'
        $Script:SecondSid = 'S-1-5-21-100-200-300-1102'
        $Rule = [PSCustomObject]@{
            IdentityReference = $Script:TargetSid
            AccessControlType = 'Allow'
            AccessMask        = 983551
            ObjectType        = [guid]::Empty
        }
        $Script:Descriptor = [PSCustomObject]@{ AccessRules = @($Rule) }
        Add-Member -InputObject $Script:Descriptor -MemberType ScriptMethod -Name GetAccessRules -Value { $this.AccessRules }
        $Script:Target = [PSCustomObject]@{
            Name                                        = 'APP01'
            DistinguishedName                           = 'CN=APP01,OU=Servers,DC=example,DC=test'
            ObjectGUID                                  = [guid]'55555555-5555-5555-5555-555555555555'
            ObjectClass                                 = @('top', 'person', 'computer')
            ObjectCategory                              = 'CN=Computer,CN=Schema,CN=Configuration,DC=example,DC=test'
            SamAccountName                              = 'APP01$'
            UserAccountControl                          = 0
            Enabled                                     = $true
            'msDS-AllowedToActOnBehalfOfOtherIdentity' = $Script:Descriptor
        }
        $Script:ResolvedComputer = [PSCustomObject]@{
            Name = 'DELEGATOR01'; ObjectClass = @('top', 'person', 'computer'); SamAccountName = 'DELEGATOR01$';
            DistinguishedName = 'CN=DELEGATOR01,OU=Servers,DC=example,DC=test'; ObjectGUID = [guid]'66666666-6666-6666-6666-666666666666'; Enabled = $true; UserAccountControl = 0
        }
        Mock -CommandName Get-ADDomain -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{ DNSRoot = 'example.test' } }
        Mock -CommandName Get-ADForest -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{ Name = 'example.test' } }
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            if ($PSBoundParameters.ContainsKey('Identity')) { $Script:ResolvedComputer }
            else { @($Script:Target) }
        }
    }

    It 'returns no finding when the attribute is absent' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{ Name = 'EMPTY'; ObjectClass = @('computer') } }
        @(Get-TechHubADRBCD).Count | Should -Be 0
    }

    It 'handles a valid descriptor and one resolvable computer trustee' {
        $Result = @(Get-TechHubADRBCD)[0]
        $Result.Evidence.SecurityDescriptorPresent | Should -BeTrue
        $Result.Evidence.AllowedIdentities.Count | Should -Be 1
        $Result.Evidence.ResolvedIdentities[0].ObjectType | Should -Be 'Computer'
        $Result.Evidence.UnresolvedSids.Count | Should -Be 0
    }

    It 'handles multiple trustees' {
        $SecondRule = [PSCustomObject]@{ IdentityReference = $Script:SecondSid; AccessControlType = 'Allow'; AccessMask = 983551; ObjectType = [guid]::Empty }
        $Script:Descriptor.AccessRules = @($Rule, $SecondRule)
        $Result = @(Get-TechHubADRBCD)[0]
        $Result.Evidence.AllowedIdentities.Count | Should -Be 2
        $Result.Severity | Should -Be 'Medium'
    }

    It 'records an unresolved SID without treating it as a collection error' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            if ($PSBoundParameters.ContainsKey('Identity')) { throw [System.Exception]::new('SID not found') }
            @($Script:Target)
        }
        $Result = @(Get-TechHubADRBCD)[0]
        $Result.Status | Should -Be 'Finding'
        $Result.Evidence.UnresolvedSids | Should -Contain $Script:TargetSid
        $Result.Confidence | Should -Be 'Medium'
    }

    It 'identifies a user and group trustee' {
        $UserSid = 'S-1-5-21-100-200-300-1201'
        $GroupSid = 'S-1-5-21-100-200-300-1202'
        $UserRule = [PSCustomObject]@{ IdentityReference = $UserSid; AccessControlType = 'Allow'; AccessMask = 1; ObjectType = [guid]::Empty }
        $GroupRule = [PSCustomObject]@{ IdentityReference = $GroupSid; AccessControlType = 'Allow'; AccessMask = 1; ObjectType = [guid]::Empty }
        $Script:Descriptor.AccessRules = @($UserRule, $GroupRule)
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            if (-not $PSBoundParameters.ContainsKey('Identity')) { return @($Script:Target) }
            if ($Identity -eq $UserSid) { return [PSCustomObject]@{ Name = 'svc-app'; ObjectClass = @('user'); Enabled = $false; SamAccountName = 'svc-app' } }
            return [PSCustomObject]@{ Name = 'App-Delegation'; ObjectClass = @('group'); Enabled = $true; SamAccountName = 'App-Delegation' }
        }
        $Result = @(Get-TechHubADRBCD)[0]
        $Result.Evidence.ResolvedIdentities.ObjectType | Should -Contain 'User'
        $Result.Evidence.ResolvedIdentities.ObjectType | Should -Contain 'Group'
        ($Result.Evidence.ResolvedIdentities | Where-Object ObjectType -eq 'User').Enabled | Should -BeFalse
    }

    It 'classifies a sensitive target with an unresolved trustee as critical' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            if ($PSBoundParameters.ContainsKey('Identity')) { throw [System.Exception]::new('SID not found') }
            @($Script:Target)
        }
        $Result = @(Get-TechHubADRBCD -SensitiveTargetPatterns 'APP*')[0]
        $Result.Severity | Should -Be 'Critical'
    }

    It 'classifies an approved identity as a documented low-risk configuration' {
        $Result = @(Get-TechHubADRBCD -ApprovedIdentityPatterns $Script:TargetSid)[0]
        $Result.Severity | Should -Be 'Low'
    }

    It 'classifies an excluded identity as informational and not applicable' {
        $Result = @(Get-TechHubADRBCD -ExcludedIdentityPatterns $Script:TargetSid)[0]
        $Result.Severity | Should -Be 'Informational'
        $Result.Status | Should -Be 'NotApplicable'
    }

    It 'reports a descriptor that cannot be read' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith {
            $BrokenTarget = [PSCustomObject]@{ Name = 'BROKEN'; ObjectClass = @('computer'); 'msDS-AllowedToActOnBehalfOfOtherIdentity' = [PSCustomObject]@{} }
            @($BrokenTarget)
        }
        $Result = @(Get-TechHubADRBCD)[0]
        $Result.Status | Should -Be 'Error'
        $Result.Evidence.SecurityDescriptorPresent | Should -BeFalse
    }

    It 'handles empty results and LDAP errors' {
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith { @() }
        @(Get-TechHubADRBCD).Count | Should -Be 0
        Mock -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -MockWith { throw [System.Exception]::new('LDAP failure') }
        @(Get-TechHubADRBCD -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'returns the complete finding contract and read-only marker' {
        $Result = @(Get-TechHubADRBCD)[0]
        $Properties = @('AssessmentId', 'CheckId', 'CheckName', 'FindingId', 'Title', 'Description', 'Category', 'Severity', 'Confidence', 'Status', 'AffectedObject', 'ObjectType', 'DistinguishedName', 'SamAccountName', 'ObjectGuid', 'Evidence', 'Risk', 'Recommendation', 'References', 'CollectedAt', 'Domain', 'Forest', 'DomainController', 'IsReadOnly')
        foreach ($Property in $Properties) { $Result.PSObject.Properties.Name | Should -Contain $Property }
        $Result.CheckId | Should -Be 'AD-RBCD'
        $Result.CheckName | Should -Be 'Resource-Based Constrained Delegation'
        $Result.Category | Should -Be 'Delegation'
        $Result.IsReadOnly | Should -BeTrue
    }

    It 'supports verbose output and passes server and search base' {
        { Get-TechHubADRBCD -Verbose 4>&1 | Out-Null } | Should -Not -Throw
        Get-TechHubADRBCD -Server 'dc01.example.test' -SearchBase 'OU=Servers,DC=example,DC=test' | Out-Null
        Assert-MockCalled -CommandName Get-ADObject -ModuleName TechHub.ActiveDirectory -ParameterFilter { $Server -eq 'dc01.example.test' -and $SearchBase -eq 'OU=Servers,DC=example,DC=test' } -Times 1
    }

    It 'contains no Active Directory modification cmdlets' {
        $Source = Get-Content -Path (Join-Path $PSScriptRoot '..\Public\Get-TechHubADRBCD.ps1') -Raw
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse
    }
}
