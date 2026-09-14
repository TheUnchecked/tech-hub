#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteCimQuery {

    <#
    .SYNOPSIS
        Internal read-only CIM transport helper for the remote collectors.

    .DESCRIPTION
        Establishes a temporary CIM session to a remote computer and runs
        the supplied read-only script block against it.

        Transport order:
            1. WSMan
            2. DCOM

        Before each transport is attempted, a bounded TCP reachability
        check runs against its port (5985 for WSMan, 135 for DCOM/RPC),
        so a powered-off or unreachable host fails fast instead of
        letting New-CimSession hang for minutes.

        The session is always removed again, whether the script block
        succeeds or fails.

        This function performs no write operations and never falls back
        to Invoke-Command/PSRemoting.

    .PARAMETER ComputerName
        Remote computer name.

    .PARAMETER Credential
        Optional alternate credential.

    .PARAMETER ScriptBlock
        Read-only script block. Receives the established CimSession as
        its only parameter and must return the data to collect.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for each transport's reachability check, in
        seconds. Default 10.

    .OUTPUTS
        Transport
        Status
        Data
        ErrorType
        ErrorMessage
    #>

    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$TimeoutSeconds = 10
    )

    $Session = $null
    $Transport = 'None'
    $ConnectionErrorMessage = $null

    # ============================================================
    # 1. WSMAN
    # ============================================================

    if (Test-AssessmentADRemotePortOpen -ComputerName $ComputerName -Port 5985 -TimeoutSeconds $TimeoutSeconds) {

        try {

            $WSManParams = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $WSManParams.Credential = $Credential
            }

            $Session = New-CimSession @WSManParams

            $Transport = 'WSMan'
        }
        catch {

            $ConnectionErrorMessage = $_.Exception.Message
            $Session = $null
        }
    }
    else {

        $ConnectionErrorMessage = "WinRM (port 5985) on $ComputerName did not respond within $TimeoutSeconds second(s)."
    }

    # ============================================================
    # 2. DCOM FALLBACK
    # ============================================================

    if ($null -eq $Session) {

        if (Test-AssessmentADRemotePortOpen -ComputerName $ComputerName -Port 135 -TimeoutSeconds $TimeoutSeconds) {

            try {

                $DcomOption = New-CimSessionOption -Protocol Dcom

                $DcomParams = @{
                    ComputerName  = $ComputerName
                    SessionOption = $DcomOption
                    ErrorAction   = 'Stop'
                }

                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $DcomParams.Credential = $Credential
                }

                $Session = New-CimSession @DcomParams

                $Transport = 'DCOM'
            }
            catch {

                $ConnectionErrorMessage = $_.Exception.Message
                $Session = $null
            }
        }
        else {

            $ConnectionErrorMessage = "RPC/DCOM (port 135) on $ComputerName did not respond within $TimeoutSeconds second(s)."
        }
    }

    # ============================================================
    # 3. NO TRANSPORT AVAILABLE
    # ============================================================

    if ($null -eq $Session) {

        return [PSCustomObject][ordered]@{

            Transport = 'None'

            Status = 'NotAvailable'

            Data = $null

            ErrorType = 'RemoteQueryError'

            ErrorMessage =
                if (-not [string]::IsNullOrWhiteSpace($ConnectionErrorMessage)) {
                    $ConnectionErrorMessage
                }
                else {
                    'Unable to establish a CIM session (WSMan and DCOM both failed).'
                }
        }
    }

    # ============================================================
    # 4. EXECUTE READ-ONLY SCRIPT BLOCK
    # ============================================================

    try {

        $Data = & $ScriptBlock $Session

        [PSCustomObject][ordered]@{

            Transport = $Transport

            Status = 'Available'

            Data = $Data

            ErrorType = $null

            ErrorMessage = $null
        }
    }
    catch {

        [PSCustomObject][ordered]@{

            Transport = $Transport

            Status = 'NotAvailable'

            Data = $null

            ErrorType = 'RemoteQueryError'

            ErrorMessage = $_.Exception.Message
        }
    }
    finally {

        if ($null -ne $Session) {

            Remove-CimSession `
                -CimSession $Session `
                -ErrorAction SilentlyContinue
        }
    }
}
