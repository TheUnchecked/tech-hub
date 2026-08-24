@{
    RootModule        = 'TechHub.ActiveDirectory.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b5e2a4b4-0a4d-4d18-a0df-35f65f4df2a8'
    Author            = 'TheUnchecked'
    CompanyName       = 'TheUnchecked'
    Description       = 'Read-only Active Directory security assessment functions.'
    PowerShellVersion = '5.1'

    CompatiblePSEditions = @(
        'Desktop'
    )

    FunctionsToExport = @(
        # ------------------------------------------------------------
        # Active Directory checks
        # ------------------------------------------------------------

        'Get-TechHubADInventory'
        'Get-TechHubADUnconstrainedDelegation'
        'Get-TechHubADConstrainedDelegation'
        'Get-TechHubADRBCD'
        'Get-TechHubADPrivilegedGroup'
        'Get-TechHubADServiceAccounts'

        # ------------------------------------------------------------
        # Remote assessment collectors
        # ------------------------------------------------------------

        'Get-TechHubADRemoteIISAppPoolAccounts'
        'Get-TechHubADRemoteLocalGroupMembers'
        'Get-TechHubADRemoteNetworkShareACLs'
        'Get-TechHubADRemoteScheduledTaskAccounts'
        'Get-TechHubADRemoteOSInfo'
        'Get-TechHubADRemoteWindowsFeatures'

        # ------------------------------------------------------------
        # Assessment engine
        # ------------------------------------------------------------

        'New-TechHubADAssessmentResult'
        'New-TechHubADCheckRegistry'
        'Invoke-TechHubADAssessment'
        'Invoke-TechHubADRemoteAssessment'

        # ------------------------------------------------------------
        # Provider
        # ------------------------------------------------------------

        'New-TechHubADProvider'

        # ------------------------------------------------------------
        # Exporters
        # ------------------------------------------------------------

        'Export-TechHubADAssessmentJson'
        'Export-TechHubADAssessmentCsv'
        'Export-TechHubADAssessmentHtml'
    )

    CmdletsToExport = @()

    VariablesToExport = @()

    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'ActiveDirectory'
                'Security'
                'Assessment'
                'Inventory'
                'ReadOnly'
                'PowerShell'
            )
        }
    }
}