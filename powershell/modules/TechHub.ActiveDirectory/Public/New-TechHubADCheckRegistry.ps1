function New-TechHubADCheckRegistry {
    [CmdletBinding()]
    param ()

    $Registry = [TechHubADCheckRegistry]::new()
    $Definitions = @(
        [TechHubADCheckDefinition]::new('AD-UNCONSTRAINED-DELEGATION', 'Unconstrained Delegation', 'Detects accounts configured with the TRUSTED_FOR_DELEGATION flag.', 'Delegation', '1.0.0', $true, $true, 'Get-TechHubADUnconstrainedDelegation', @('TechHubADProvider'), @('ActiveDirectory'), @('Security', 'Delegation', 'ReadOnly'))
        [TechHubADCheckDefinition]::new('AD-CONSTRAINED-DELEGATION', 'Constrained Delegation', 'Detects accounts configured with msDS-AllowedToDelegateTo.', 'Delegation', '1.0.0', $true, $true, 'Get-TechHubADConstrainedDelegation', @('TechHubADProvider'), @('ActiveDirectory'), @('Security', 'Delegation', 'ReadOnly'))
        [TechHubADCheckDefinition]::new('AD-RBCD', 'Resource-Based Constrained Delegation', 'Detects resource-based constrained delegation security descriptors.', 'Delegation', '1.0.0', $true, $true, 'Get-TechHubADRBCD', @('TechHubADProvider'), @('ActiveDirectory'), @('Security', 'Delegation', 'ReadOnly'))
        [TechHubADCheckDefinition]::new('AD-PRIVILEGED-GROUP', 'Privileged Groups', 'Analyzes membership of configured privileged Active Directory groups.', 'PrivilegedAccess', '1.0.0', $true, $true, 'Get-TechHubADPrivilegedGroup', @('TechHubADProvider'), @('ActiveDirectory'), @('Security', 'PrivilegedAccess', 'ReadOnly'))
    )

    foreach ($Definition in $Definitions) {
        $Registry.Register($Definition)
    }
    $Registry
}
