#requires -Version 5.1

Set-StrictMode -Version Latest

function Test-TechHubADDnsServerAvailability {

    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {

        $DnsServerModule = Get-Module `
            -ListAvailable `
            -Name 'DnsServer' `
            -ErrorAction SilentlyContinue

        if ($null -ne $DnsServerModule) {
            return $true
        }

        # Test / mock compatibility: Pester tests may provide a mocked
        # Get-Module result without installing the real DnsServer module.
        $ModuleProbe = Get-Module `
            -Name 'DnsServer' `
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
