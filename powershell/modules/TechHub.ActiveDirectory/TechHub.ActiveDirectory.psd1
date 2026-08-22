@{
    RootModule        = 'TechHub.ActiveDirectory.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b5e2a4b4-0a4d-4d18-a0df-35f65f4df2a8'
    Author            = 'TheUnchecked'
    CompanyName       = 'TheUnchecked'
    Description       = 'Read-only Active Directory security assessment functions.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop')

    RequiredModules   = @('ActiveDirectory')

    FunctionsToExport = @(
        'Get-TechHubADUnconstrainedDelegation'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'ActiveDirectory'
                'Security'
                'Assessment'
                'ReadOnly'
                'PowerShell'
            )
        }
    }
}
