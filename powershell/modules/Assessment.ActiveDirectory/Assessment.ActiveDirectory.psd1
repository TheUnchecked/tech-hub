@{
    RootModule        = 'Assessment.ActiveDirectory.psm1'
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
    # Active Directory security checks (facts only, no severity)
    # ------------------------------------------------------------

    'Get-AssessmentADUnconstrainedDelegation'
    'Get-AssessmentADConstrainedDelegation'
    'Get-AssessmentADRBCD'
    'Get-AssessmentADPrivilegedGroup'
    'Get-AssessmentADInventory'

    # ------------------------------------------------------------
    # Remote infrastructure collectors
    # ------------------------------------------------------------

    'Get-AssessmentADRemoteTargets'
    'Get-AssessmentADRemoteOSInfo'
    'Get-AssessmentADRemoteWindowsFeatures'
    'Get-AssessmentADRemoteServiceAccounts'
    'Get-AssessmentADRemoteScheduledTaskAccounts'
    'Get-AssessmentADRemoteIISAppPoolAccounts'
    'Get-AssessmentADRemoteNetworkShareACLs'
    'Get-AssessmentADRemoteUserRightAssignments'
    'Get-AssessmentADRemoteLocalGroupMembers'
    'Get-AssessmentADRemoteLocalGroups'

    # ------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------

    'Invoke-AssessmentADAssessment'
    'Invoke-AssessmentADRemoteAssessment'
    'Invoke-AssessmentADRemoteLocalGroups'

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