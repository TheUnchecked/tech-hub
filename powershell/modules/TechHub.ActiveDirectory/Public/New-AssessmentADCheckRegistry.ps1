function New-AssessmentADCheckRegistry {
    [CmdletBinding()]
    param ()

    $Registry = [TechHubADCheckRegistry]::new()

    $Definitions = @(

        # ============================================================
        # ACTIVE DIRECTORY
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-UNCONSTRAINED-DELEGATION',
            'Unconstrained Delegation',
            'Detects accounts configured with the TRUSTED_FOR_DELEGATION flag.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADUnconstrainedDelegation',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-CONSTRAINED-DELEGATION',
            'Constrained Delegation',
            'Detects accounts configured with msDS-AllowedToDelegateTo.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADConstrainedDelegation',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-RBCD',
            'Resource-Based Constrained Delegation',
            'Detects resource-based constrained delegation security descriptors.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRBCD',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-KERBEROASTING',
            'Kerberoasting Exposure',
            'Detects SPN-bearing user accounts that can be targeted for Kerberoasting, prioritizing privileged and RC4-only accounts.',
            'Kerberos',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADKerberoasting',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Kerberos', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-ASREP-ROASTING',
            'AS-REP Roasting Exposure',
            'Detects accounts configured with DONT_REQUIRE_PREAUTH, allowing an offline attack against their AS-REP without valid credentials.',
            'Kerberos',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADASREPRoasting',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Kerberos', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-KRBTGT-PASSWORD-AGE',
            'krbtgt Password Age',
            'Reports the age of the krbtgt account password, a key indicator of golden ticket exposure and AD backup/recovery hygiene.',
            'Kerberos',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADKrbtgtPasswordAge',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Kerberos', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-PASSWORD-POLICY',
            'Password Policy',
            'Evaluates the default domain password policy and any Fine-Grained Password Policies against baseline security expectations.',
            'Authentication',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADPasswordPolicy',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Authentication', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-DCSYNC-RIGHTS',
            'DCSync Replication Rights',
            'Detects principals holding directory replication rights (DS-Replication-Get-Changes / -All) outside the expected default holders.',
            'PrivilegedAccess',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADDCSyncRights',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'PrivilegedAccess', 'ACL', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-SHADOW-ADMIN',
            'Shadow Admin Rights',
            'Detects principals holding GenericAll/WriteDacl/WriteOwner/GenericWrite rights on the domain root or AdminSDHolder outside the expected default holders.',
            'PrivilegedAccess',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADShadowAdminRights',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'PrivilegedAccess', 'ACL', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-PRIVILEGED-GROUP',
            'Privileged Groups',
            'Analyzes membership of configured privileged Active Directory groups.',
            'PrivilegedAccess',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADPrivilegedGroup',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'PrivilegedAccess', 'ReadOnly')
        )

        # ============================================================
        # REMOTE LOCAL GROUPS
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-REMOTE-LOCAL-GROUPS',
            'Remote Local Group Membership',
            'Analyzes local group membership on remote Windows computers.',
            'PrivilegedAccess',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRemoteLocalGroups',
            @(),
            @('ActiveDirectory', 'RemoteManagement'),
            @(
                'Security',
                'PrivilegedAccess',
                'RemoteAssessment',
                'ReadOnly'
            )
        )
    )

    foreach ($Definition in $Definitions) {
        $Registry.Register($Definition)
    }

    $Registry
}