#Requires -Version 5.1

Set-StrictMode -Version Latest

function Test-AssessmentADRemotePortOpen {
    <#
    .SYNOPSIS
        Tests whether a TCP port on a remote computer accepts a connection within a bounded time.

    .DESCRIPTION
        Used by the remote collectors as a fast reachability check before
        New-CimSession/Invoke-Command, which can otherwise hang for minutes
        against a powered-off or unreachable host. Performs a non-blocking
        TCP connect and waits at most TimeoutSeconds for it to complete.

    .PARAMETER ComputerName
        Remote computer name or address.

    .PARAMETER Port
        TCP port to test.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the connection, in seconds. Default 10.

    .OUTPUTS
        [bool] $true if the port accepted a connection, otherwise $false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter()]
        [int]$TimeoutSeconds = 10
    )

    $Client = $null

    try {
        $Client = New-Object System.Net.Sockets.TcpClient

        $AsyncResult = $Client.BeginConnect($ComputerName, $Port, $null, $null)

        $Completed = $AsyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))

        if (-not $Completed) {
            return $false
        }

        $Client.EndConnect($AsyncResult)

        return $Client.Connected
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $Client) {
            $Client.Close()
        }
    }
}
