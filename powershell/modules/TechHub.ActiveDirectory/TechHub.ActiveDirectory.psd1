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

    'Get-AssessmentADInventory'
    'Get-AssessmentADUnconstrainedDelegation'
    'Get-AssessmentADConstrainedDelegation'
    'Get-AssessmentADRBCD'
    'Get-AssessmentADPrivilegedGroup'
    'Get-AssessmentADServiceAccounts'
    'Get-AssessmentADRemoteTargets'
    'Get-AssessmentADKerberoasting'
    'Get-AssessmentADASREPRoasting'
    'Get-AssessmentADKrbtgtPasswordAge'
    'Get-AssessmentADPasswordPolicy'
    'Get-AssessmentADDCSyncRights'
    'Get-AssessmentADShadowAdminRights'
    'Get-AssessmentADStaleAccounts'
    'Get-AssessmentADPasswordNeverExpiresAccounts'
    'Get-AssessmentADProtectedUsersCoverage'
    'Get-AssessmentADRemoteAuthenticationHardening'
    'Get-AssessmentADRemoteCredentialGuardStatus'
    'Get-AssessmentADRemoteObsoleteOperatingSystem'
    'Get-AssessmentADRemoteAuditPolicy'
    'Get-AssessmentADDNSZoneSecurity'
    'Get-AssessmentADRecycleBinStatus'

    # ------------------------------------------------------------
    # Remote assessment collectors
    # ------------------------------------------------------------

    'Get-AssessmentADRemoteIISAppPoolAccounts'
    'Get-AssessmentADRemoteLocalGroupMembers'
    'Get-AssessmentADRemoteNetworkShareACLs'
    'Get-AssessmentADRemoteScheduledTaskAccounts'
    'Get-AssessmentADRemoteOSInfo'
    'Get-AssessmentADRemoteWindowsFeatures'
    'Get-AssessmentADRemoteLocalGroups'

    # ------------------------------------------------------------
    # Remote assessment orchestration
    # ------------------------------------------------------------

    'Invoke-AssessmentADRemoteLocalGroups'

    # ------------------------------------------------------------
    # Assessment engine
    # ------------------------------------------------------------

    'New-AssessmentADAssessmentResult'
    'New-AssessmentADCheckRegistry'
    'Invoke-AssessmentADAssessment'
    'Invoke-AssessmentADRemoteAssessment'
    'Invoke-AssessmentADFullAssessment'

    # ------------------------------------------------------------
    # Provider
    # ------------------------------------------------------------

    'New-AssessmentADProvider'

    # ------------------------------------------------------------
    # Exporters
    # ------------------------------------------------------------

    'Export-AssessmentADAssessmentJson'
    'Export-AssessmentADAssessmentCsv'
    'Export-AssessmentADAssessmentHtml'
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