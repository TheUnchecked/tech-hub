function Get-AssessmentADDNSZoneSecurity {
    <#
    .SYNOPSIS
        Evaluates dynamic update and zone transfer settings of
        AD-integrated DNS zones.

    .DESCRIPTION
        Requires the DnsServer PowerShell module in addition to
        ActiveDirectory - a distinct dependency from every other check in
        this module. It is typically available on a domain controller
        that also holds the DNS server role.

        Flags AD-integrated primary zones configured with:

        - DynamicUpdate = NonsecureAndSecure (unauthenticated dynamic
          updates are accepted, a known ADIDNS attack surface).
        - SecureSecondaries = TransferAnyServer (zone transfers are
          permitted to any server, allowing full zone enumeration).

    .PARAMETER Server
        DNS server (typically a domain controller with the DNS role) to
        query. Optional; omitted, the ActiveDirectory module's normal
        discovery is used for AD context, and the local computer is
        assumed to be the DNS server.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Forest,

        [Parameter()]
        [string]$DomainController,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-DNS-ZONE-SECURITY'
    $CheckName = 'DNS Zone Security'

    if ($null -eq $Provider) {
        $Provider = New-AssessmentADProvider -Server $Server
    }

    $DomainResult = $null
    $ForestResult = $null

    try {
        $DomainResult = $Provider.GetDomainInformation()
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect domain context from provider: {0}' -f
            $_.Exception.Message
        )
    }

    try {
        $ForestResult = $Provider.GetForestInformation()
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect forest context from provider: {0}' -f
            $_.Exception.Message
        )
    }

    if (
        [string]::IsNullOrWhiteSpace($Domain) -and
        $null -ne $DomainResult -and
        $DomainResult.Status -eq 'Available' -and
        @($DomainResult.Data).Count -gt 0
    ) {
        $DomainData = @($DomainResult.Data)[0]

        if ($null -ne $DomainData.PSObject.Properties['DNSRoot']) {
            $Domain = [string]$DomainData.PSObject.Properties['DNSRoot'].Value
        }
    }

    if (
        [string]::IsNullOrWhiteSpace($Forest) -and
        $null -ne $ForestResult -and
        $ForestResult.Status -eq 'Available' -and
        @($ForestResult.Data).Count -gt 0
    ) {
        $ForestData = @($ForestResult.Data)[0]

        if ($null -ne $ForestData.PSObject.Properties['Name']) {
            $Forest = [string]$ForestData.PSObject.Properties['Name'].Value
        }
    }

    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        $DomainController = $Server
    }

    try {
        Write-Verbose -Message 'Requesting DNS zones from TechHubADProvider.'

        $ZonesResult = $Provider.GetDnsZones()
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $ZonesResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $ZonesStatus = [string]$ZonesResult.Status

    if ($ZonesStatus -eq 'NotAvailable' -or $ZonesStatus -eq 'Error') {

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'DNS' `
            -Title 'DNS zone security assessment unavailable' `
            -Description 'The provider could not retrieve DNS zones. This check requires the DnsServer module on the target.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $ZonesStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $null; ObjectClass = 'DnsZone'; Enabled = $null }) `
            -ObjectType 'DnsZone' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $ZonesStatus; ErrorType = $ZonesResult.ErrorType; ErrorMessage = $ZonesResult.ErrorMessage }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Ensure the DnsServer module is available on the target and that it also hosts the DNS server role, then rerun the assessment.' `
            -References @('https://learn.microsoft.com/windows-server/networking/dns/dns-top') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $Zones = @(
        @($ZonesResult.Data) |
            Where-Object {
                $_.PSObject.Properties['IsDsIntegrated'] -and
                $_.IsDsIntegrated -eq $true -and
                $_.PSObject.Properties['ZoneType'] -and
                [string]$_.ZoneType -eq 'Primary'
            }
    )

    Write-Verbose -Message ('Evaluating {0} AD-integrated primary zone(s).' -f $Zones.Count)

    foreach ($Zone in $Zones) {

        $ZoneName = [string]$Zone.ZoneName
        $DynamicUpdate = if ($Zone.PSObject.Properties['DynamicUpdate']) { [string]$Zone.DynamicUpdate } else { $null }

        try {
            $TransferResult = $Provider.GetDnsZoneTransferSettings($ZoneName)
        }
        catch {
            Write-Error -ErrorRecord $_
            continue
        }

        if ($null -eq $TransferResult) {
            continue
        }

        $TransferStatus = [string]$TransferResult.Status

        if ($TransferStatus -eq 'NotAvailable' -or $TransferStatus -eq 'Error') {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'DNS' `
                -Title ('DNS zone security assessment unavailable for {0}' -f $ZoneName) `
                -Description 'The provider could not retrieve zone transfer settings for this zone.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status $TransferStatus `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $ZoneName; ObjectClass = 'DnsZone'; Enabled = $null }) `
                -ObjectType 'DnsZone' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $TransferStatus; ErrorType = $TransferResult.ErrorType; ErrorMessage = $TransferResult.ErrorMessage }) `
                -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
                -Recommendation 'Restore provider availability and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/networking/dns/dns-top') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        $TransferSettings = @($TransferResult.Data) | Select-Object -First 1
        $SecureSecondaries = if ($null -ne $TransferSettings -and $TransferSettings.PSObject.Properties['SecureSecondaries']) { [string]$TransferSettings.SecureSecondaries } else { $null }

        $Weaknesses = @()
        $Severity = 'Informational'

        if ($DynamicUpdate -eq 'NonsecureAndSecure') {
            $Weaknesses += 'Dynamic updates are accepted from unauthenticated clients (DynamicUpdate = NonsecureAndSecure).'
            $Severity = 'High'
        }

        if ($SecureSecondaries -eq 'TransferAnyServer') {
            $Weaknesses += 'Zone transfers are permitted to any server (SecureSecondaries = TransferAnyServer).'
            if ($Severity -ne 'High') { $Severity = 'Medium' }
        }

        $Risk = 'This zone''s dynamic update and zone transfer settings meet the hardening baseline.'

        if ($Weaknesses.Count -gt 0) {
            $Risk = 'A weakly configured AD-integrated zone can allow unauthenticated record injection (ADIDNS poisoning/hijacking of service names) or full zone enumeration by any host. Weaknesses: ' + ($Weaknesses -join ' ')
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'DNS' `
            -Title ('DNS zone security: {0}' -f $ZoneName) `
            -Description 'Evaluates dynamic update and zone transfer settings for an AD-integrated primary zone.' `
            -Severity $Severity `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $ZoneName; ObjectClass = 'DnsZone'; Enabled = $null }) `
            -ObjectType 'DnsZone' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    ZoneName          = $ZoneName
                    DynamicUpdate     = $DynamicUpdate
                    SecureSecondaries = $SecureSecondaries
                    Weaknesses        = $Weaknesses
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Set DynamicUpdate to Secure for AD-integrated zones, and set SecureSecondaries to TransferToSecureServers or NoTransfer unless zone transfer to specific secondaries is a documented requirement.' `
            -References @(
                'https://learn.microsoft.com/windows-server/networking/dns/dns-top'
                'https://learn.microsoft.com/troubleshoot/windows-server/networking/dynamic-update-secure-dynamic-update'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
