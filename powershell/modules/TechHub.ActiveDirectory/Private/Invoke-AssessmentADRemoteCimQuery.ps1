#requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteCimQuery {

    <#
    .SYNOPSIS
        Shared read-only CIM transport for remote assessment collectors.

    .DESCRIPTION
        Establishes a CIM session against a remote computer and executes
        the supplied read-only script block against it, then always
        closes the session.

        Transport preference:

        1. CIM / WSMan
        2. CIM / DCOM

        This helper never accepts arbitrary command strings. Callers
        pass a script block that receives the established CIM session
        as its only argument; the helper does not interpret, modify,
        or execute anything beyond invoking that script block.

    .PARAMETER ComputerName
        Remote computer name.

    .PARAMETER Credential
        Optional alternate credential.

    .PARAMETER UseSSL
        Requests the WSMan transport over HTTPS. Has no effect on the
        DCOM fallback, which does not use WSMan.

    .PARAMETER ScriptBlock
        Read-only script block. Receives the established CIM session
        as its only argument, for example:

            { param($Session) Get-CimInstance -CimSession $Session ... }

    .OUTPUTS
        ComputerName
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

        [Parameter()]
        [switch]$UseSSL,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock
    )

    $Session = $null
    $Transport = 'None'

    # ================================================================
    # 1. ESTABLISH CIM SESSION (WSMan, then DCOM fallback)
    # ================================================================

    try {

        $WSManParams = @{
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }

        if ($PSBoundParameters.ContainsKey('Credential')) {
            $WSManParams.Credential = $Credential
        }

        if ($UseSSL) {
            $WSManParams.SessionOption = New-CimSessionOption -UseSsl
        }

        try {

            $Session = New-CimSession @WSManParams

            $Transport = 'WSMan'
        }
        catch {

            Write-Verbose `
                "[$ComputerName] WSMan CIM session failed. Falling back to DCOM."

            $DCOMParams = @{
                ComputerName  = $ComputerName
                ErrorAction   = 'Stop'
                SessionOption = New-CimSessionOption -Protocol Dcom
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $DCOMParams.Credential = $Credential
            }

            $Session = New-CimSession @DCOMParams

            $Transport = 'DCOM'
        }
    }
    catch {

        return [PSCustomObject][ordered]@{

            ComputerName = $ComputerName
            Transport    = 'None'
            Status       = 'NotAvailable'
            Data         = $null
            ErrorType    = 'RemoteTransportUnavailable'
            ErrorMessage = $_.Exception.Message
        }
    }

    # ================================================================
    # 2. EXECUTE READ-ONLY SCRIPT BLOCK
    # ================================================================

    try {

        $Data = & $ScriptBlock $Session

        [PSCustomObject][ordered]@{

            ComputerName = $ComputerName
            Transport    = $Transport
            Status       = 'Available'
            Data         = $Data
            ErrorType    = $null
            ErrorMessage = $null
        }
    }
    catch {

        [PSCustomObject][ordered]@{

            ComputerName = $ComputerName
            Transport    = $Transport
            Status       = 'Error'
            Data         = $null
            ErrorType    = 'RemoteQueryError'
            ErrorMessage = $_.Exception.Message
        }
    }
    finally {

        if ($Session) {

            Remove-CimSession `
                -CimSession $Session `
                -ErrorAction SilentlyContinue
        }
    }
}
