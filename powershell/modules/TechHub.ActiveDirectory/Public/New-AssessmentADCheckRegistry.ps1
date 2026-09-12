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

        # ============================================================
        # ACCOUNT HYGIENE
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-STALE-ACCOUNTS',
            'Stale Active Directory Accounts',
            'Detects enabled user and computer accounts that have not logged on within a configurable threshold.',
            'AccountHygiene',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADStaleAccounts',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'AccountHygiene', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-PASSWORD-NEVER-EXPIRES',
            'Password Never Expires',
            'Detects accounts configured so their password never expires, prioritizing privileged accounts.',
            'AccountHygiene',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADPasswordNeverExpiresAccounts',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'AccountHygiene', 'ReadOnly')
        )

        # ============================================================
        # HARDENING
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-PROTECTED-USERS-COVERAGE',
            'Protected Users Coverage',
            'Detects privileged group members who are not also members of the Protected Users group.',
            'Hardening',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADProtectedUsersCoverage',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Hardening', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-AUTH-HARDENING',
            'Legacy Authentication Hardening',
            'Evaluates LmCompatibilityLevel, LM hash storage, and LDAP signing on remote Windows computers (domain controllers by default).',
            'Hardening',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRemoteAuthenticationHardening',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Hardening', 'RemoteAssessment', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-CREDENTIAL-GUARD',
            'Credential Guard Status',
            'Evaluates whether virtualization-based security and Credential Guard are running on remote Windows computers (domain controllers by default).',
            'Hardening',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRemoteCredentialGuardStatus',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Hardening', 'RemoteAssessment', 'ReadOnly')
        )

        [TechHubADCheckDefinition]::new(
            'AD-OBSOLETE-OS',
            'Obsolete Operating System',
            'Flags remote Windows computers running an operating system past its mainstream end-of-support date.',
            'Hardening',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRemoteObsoleteOperatingSystem',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Hardening', 'RemoteAssessment', 'ReadOnly')
        )

        # ============================================================
        # AUDITING AND LOGGING
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-AUDIT-POLICY',
            'Advanced Audit Policy Coverage',
            'Evaluates whether security-relevant Advanced Audit Policy subcategories are enabled on remote Windows computers (domain controllers by default).',
            'AuditingAndLogging',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRemoteAuditPolicy',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'AuditingAndLogging', 'RemoteAssessment', 'ReadOnly')
        )

        # ============================================================
        # DNS
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-DNS-ZONE-SECURITY',
            'DNS Zone Security',
            'Evaluates dynamic update and zone transfer settings of AD-integrated DNS zones. Requires the DnsServer module in addition to ActiveDirectory.',
            'DNS',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADDNSZoneSecurity',
            @('TechHubADProvider'),
            @('ActiveDirectory', 'DnsServer'),
            @('Security', 'DNS', 'ReadOnly')
        )

        # ============================================================
        # DISASTER RECOVERY
        # ============================================================

        [TechHubADCheckDefinition]::new(
            'AD-RECYCLE-BIN',
            'Active Directory Recycle Bin',
            'Reports whether the Active Directory Recycle Bin optional feature is enabled.',
            'DisasterRecovery',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRecycleBinStatus',
            @('TechHubADProvider'),
            @('ActiveDirectory'),
            @('Security', 'DisasterRecovery', 'ReadOnly')
        )
    )

    foreach ($Definition in $Definitions) {
        $Registry.Register($Definition)
    }

    $Registry
}