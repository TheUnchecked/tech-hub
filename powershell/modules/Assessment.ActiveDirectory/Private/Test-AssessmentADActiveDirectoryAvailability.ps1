#requires -Version 5.1

Set-StrictMode -Version Latest

function Test-AssessmentADActiveDirectoryAvailability {

    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {

        # ------------------------------------------------------------
        # 1. Check whether the ActiveDirectory module is installed
        # ------------------------------------------------------------

        $ActiveDirectoryModule = Get-Module `
            -ListAvailable `
            -Name 'ActiveDirectory' `
            -ErrorAction SilentlyContinue

        if ($null -ne $ActiveDirectoryModule) {
            return $true
        }

        # ------------------------------------------------------------
        # 2. Test / mock compatibility
        #
        # Pester tests may provide a mocked Get-Module result without
        # installing the real ActiveDirectory module.
        # ------------------------------------------------------------

        $ModuleProbe = Get-Module `
            -Name 'ActiveDirectory' `
            -ErrorAction SilentlyContinue

        if ($null -ne $ModuleProbe) {
            return $true
        }

        return $false
    }
    catch {

        return $false
    }
}