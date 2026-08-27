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