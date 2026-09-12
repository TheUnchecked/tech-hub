#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteCredentialGuardStatus {
    <#
    .SYNOPSIS
        Evaluates Windows Defender Credential Guard status on remote
        Windows computers and returns one security finding per computer.

    .DESCRIPTION
        Read-only remote assessment. Reads the Win32_DeviceGuard CIM class
        (root/Microsoft/Windows/DeviceGuard) to determine whether
        virtualization-based security is running and whether Credential
        Guard specifically is among the running security services.
        Transport is CIM/WSMan then CIM/DCOM via
        Invoke-AssessmentADRemoteCimQuery.

        When -ComputerName is not supplied, targets are discovered with
        Get-AssessmentADRemoteTargets (default -TargetType DomainController).

    .PARAMETER ComputerName
        Explicit list of computers to assess. Bypasses automatic discovery.

    .PARAMETER TargetType
        Discovery scope used when -ComputerName is not supplied. Defaults
        to 'DomainController'.

    .PARAMETER Credential
        Optional alternate credential for the remote CIM connection.

    .PARAMETER UseSSL
        Requests the WSMan transport over HTTPS.

    .PARAMETER Server
        Domain controller used to build a provider for target discovery,
        when -Provider is not supplied.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider, used for target discovery.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$TargetType = 'DomainController',

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$UseSSL,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-CREDENTIAL-GUARD'
    $CheckName = 'Credential Guard Status'
    $CredentialGuardServiceId = 1

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('ComputerName')) {

        $Targets = @(
            $ComputerName |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    else {

        if ($null -eq $Provider) {
            $Provider = New-AssessmentADProvider -Server $Server
        }

        try {
            Write-Verbose -Message ('Discovering remote targets (TargetType = {0}).' -f $TargetType)

            $Targets = @(
                Get-AssessmentADRemoteTargets -Provider $Provider -TargetType $TargetType |
                    ForEach-Object { [string]$_.ComputerName } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        catch {
            Write-Error -ErrorRecord $_
            return
        }
    }

    if ($Targets.Count -eq 0) {
        Write-Verbose -Message 'No targets were supplied or discovered; nothing to assess.'
        return
    }

    foreach ($Target in $Targets) {

        Write-Verbose -Message "[$Target] Collecting Credential Guard status."

        $CimQueryParams = @{
            ComputerName = $Target
            UseSSL       = $UseSSL
            ScriptBlock  = {
                param($Session)

                Get-CimInstance `
                    -CimSession $Session `
                    -Namespace 'root/Microsoft/Windows/DeviceGuard' `
                    -ClassName Win32_DeviceGuard `
                    -ErrorAction Stop |
                Select-Object `
                    VirtualizationBasedSecurityStatus,
                    SecurityServicesConfigured,
                    SecurityServicesRunning
            }
        }

        if ($PSBoundParameters.ContainsKey('Credential')) {
            $CimQueryParams.Credential = $Credential
        }

        $UnavailableFinding = {
            param($ErrorType, $ErrorMessage)

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('Credential Guard assessment unavailable for {0}' -f $Target) `
                -Description 'The Win32_DeviceGuard class could not be read on this computer (it may be unsupported on this OS version, or unreachable).' `
                -Severity 'Informational' `
                -Confidence 'Medium' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ErrorType = $ErrorType; ErrorMessage = $ErrorMessage }) `
                -Risk 'No security conclusion can be made because Device Guard status was unavailable.' `
                -Recommendation 'Verify remote management connectivity, or confirm whether this OS version supports Credential Guard.' `
                -References @('https://learn.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage') `
                -Domain $null `
                -Forest $null `
                -DomainController $null
        }

        try {
            $TransportResult = Invoke-AssessmentADRemoteCimQuery @CimQueryParams
        }
        catch {
            & $UnavailableFinding 'RemoteQueryError' $_.Exception.Message
            continue
        }

        if ($TransportResult.Status -ne 'Available') {
            & $UnavailableFinding $TransportResult.ErrorType $TransportResult.ErrorMessage
            continue
        }

        $Data = @($TransportResult.Data) | Select-Object -First 1

        if ($null -eq $Data) {
            & $UnavailableFinding 'NoData' 'The remote query returned no Win32_DeviceGuard instance.'
            continue
        }

        $VbsStatus = $null
        $RunningServices = @()

        if ($null -ne $Data.PSObject.Properties['VirtualizationBasedSecurityStatus']) {
            $VbsStatus = [int]$Data.PSObject.Properties['VirtualizationBasedSecurityStatus'].Value
        }

        if ($null -ne $Data.PSObject.Properties['SecurityServicesRunning']) {
            $RunningServices = @($Data.PSObject.Properties['SecurityServicesRunning'].Value)
        }

        $CredentialGuardRunning = ($RunningServices -contains $CredentialGuardServiceId)

        $Severity = 'Informational'
        $Description = 'Credential Guard is running.'

        if ($VbsStatus -ne 2) {
            $Severity = 'Medium'
            $Description = 'Virtualization-based security is not running on this computer.'
        }
        elseif (-not $CredentialGuardRunning) {
            $Severity = 'Medium'
            $Description = 'Virtualization-based security is running, but Credential Guard specifically is not among the running security services.'
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Hardening' `
            -Title ('Credential Guard status: {0}' -f $Target) `
            -Description $Description `
            -Severity $Severity `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
            -ObjectType 'Computer' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    VirtualizationBasedSecurityStatus = $VbsStatus
                    SecurityServicesRunning           = $RunningServices
                    CredentialGuardRunning            = $CredentialGuardRunning
                }
            ) `
            -Risk 'Without Credential Guard, LSASS-resident credentials are more easily extracted by tools that dump process memory (for example, Mimikatz-style attacks).' `
            -Recommendation 'Enable virtualization-based security and Credential Guard, after confirming hardware/hypervisor support and application compatibility.' `
            -References @('https://learn.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage') `
            -Domain $null `
            -Forest $null `
            -DomainController $null
    }
}
