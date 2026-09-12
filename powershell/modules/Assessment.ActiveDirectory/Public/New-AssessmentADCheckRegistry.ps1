function New-AssessmentADCheckRegistry {
    [CmdletBinding()]
    param ()

    $Registry = [AssessmentADCheckRegistry]::new()

    $Definitions = @(

        # ============================================================
        # ACTIVE DIRECTORY
        # ============================================================

        [AssessmentADCheckDefinition]::new(
            'AD-UNCONSTRAINED-DELEGATION',
            'Unconstrained Delegation',
            'Detects accounts configured with the TRUSTED_FOR_DELEGATION flag.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADUnconstrainedDelegation',
            @('AssessmentADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [AssessmentADCheckDefinition]::new(
            'AD-CONSTRAINED-DELEGATION',
            'Constrained Delegation',
            'Detects accounts configured with msDS-AllowedToDelegateTo.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADConstrainedDelegation',
            @('AssessmentADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [AssessmentADCheckDefinition]::new(
            'AD-RBCD',
            'Resource-Based Constrained Delegation',
            'Detects resource-based constrained delegation security descriptors.',
            'Delegation',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADRBCD',
            @('AssessmentADProvider'),
            @('ActiveDirectory'),
            @('Security', 'Delegation', 'ReadOnly')
        )

        [AssessmentADCheckDefinition]::new(
            'AD-PRIVILEGED-GROUP',
            'Privileged Groups',
            'Analyzes membership of configured privileged Active Directory groups.',
            'PrivilegedAccess',
            '1.0.0',
            $true,
            $true,
            'Get-AssessmentADPrivilegedGroup',
            @('AssessmentADProvider'),
            @('ActiveDirectory'),
            @('Security', 'PrivilegedAccess', 'ReadOnly')
        )

        # ============================================================
        # REMOTE LOCAL GROUPS
        # ============================================================

        [AssessmentADCheckDefinition]::new(
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