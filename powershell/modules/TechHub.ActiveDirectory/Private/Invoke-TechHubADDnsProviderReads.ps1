#requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADProviderDnsZones {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADDnsServerAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.ComputerName = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-DnsServerZone @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderDnsZoneTransferSettings {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ZoneName,

        [string]$Server
    )

    if (-not (Test-TechHubADDnsServerAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Name = $ZoneName; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.ComputerName = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-DnsServerZoneTransfer @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}
