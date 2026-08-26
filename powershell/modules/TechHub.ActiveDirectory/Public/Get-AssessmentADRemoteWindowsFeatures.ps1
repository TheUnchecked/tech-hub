#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteWindowsFeatures {

    <#
    .SYNOPSIS
        Collects installed Windows features from remote Windows computers.

    .DESCRIPTION
        Read-only remote assessment.

        Transport strategy:

        1. WinRM / WSMan
           Uses Invoke-Command and the native Windows feature
           cmdlets where available.

        2. WMI / DCOM fallback
           Uses the TechHub CIM transport abstraction and
           Win32_OptionalFeature when WSMan is unavailable.

        The collector never enables WinRM and never modifies
        the target computer.

    .PARAMETER ComputerName
        One or more remote Windows computers.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        Normalized feature records.
    #>

    [CmdletBinding()]
    param(

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'Computer',
            'CN',
            'Name',
            'PSComputerName'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        foreach ($Computer in $ComputerName) {

            if ([string]::IsNullOrWhiteSpace($Computer)) {
                continue
            }

            Write-Verbose `
                "[$Computer] Collecting Windows features."

            # ========================================================
            # 1. WSMan / WinRM
            # ========================================================

            try {

                Write-Verbose `
                    "[$Computer] Attempting Windows Features collection through WinRM."

                $invokeParams = @{
                    ComputerName = $Computer
                    ErrorAction  = 'Stop'
                    ScriptBlock  = {

                        $featureNames = @()

                        # ------------------------------------------------
                        # Windows Server
                        # ------------------------------------------------

                        $serverManagerAvailable = @(
                            Get-Module `
                                -ListAvailable `
                                -Name ServerManager `
                                -ErrorAction SilentlyContinue
                        ).Count -gt 0

                        if ($serverManagerAvailable) {

                            try {

                                Import-Module `
                                    ServerManager `
                                    -ErrorAction Stop

                                $featureNames = @(
                                    Get-WindowsFeature `
                                        -ErrorAction Stop |
                                    Where-Object {
                                        $_.Installed
                                    } |
                                    Select-Object `
                                        -ExpandProperty Name
                                )
                            }
                            catch {

                                $featureNames = @()
                            }
                        }

                        # ------------------------------------------------
                        # Windows Client
                        # ------------------------------------------------

                        if ($featureNames.Count -eq 0) {

                            try {

                                $featureNames = @(
                                    Get-WindowsOptionalFeature `
                                        -Online `
                                        -ErrorAction Stop |
                                    Where-Object {
                                        $_.State -eq 'Enabled'
                                    } |
                                    Select-Object `
                                        -ExpandProperty FeatureName
                                )
                            }
                            catch {

                                $featureNames = @()
                            }
                        }

                        # ------------------------------------------------
                        # Return normalized records
                        # ------------------------------------------------

                        foreach ($Feature in $featureNames) {

                            if (
                                -not [string]::IsNullOrWhiteSpace(
                                    [string]$Feature
                                )
                            ) {

                                [PSCustomObject][ordered]@{
                                    ComputerName = $env:COMPUTERNAME
                                    FeatureName  = [string]$Feature
                                    Status       = 'Installed'
                                    IsReadOnly   = $true
                                }
                            }
                        }
                    }
                }

                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $invokeParams.Credential = $Credential
                }

                $WinRMData = @(
                    Invoke-Command @invokeParams
                )

                Write-Verbose `
                    "[$Computer] Windows Features collected through WinRM."

                foreach ($Record in $WinRMData) {

                    [PSCustomObject][ordered]@{
                        ComputerName     = $Computer
                        FeatureName      = $Record.FeatureName
                        Status           = 'Available'
                        DataAvailability = 'Available'
                        CollectionMethod = 'WinRM'
                        ErrorType        = $null
                        ErrorMessage     = $null
                        IsReadOnly       = $true
                    }
                }

                continue
            }
            catch {

                $WinRMError = $_.Exception.Message

                Write-Verbose `
                    "[$Computer] WinRM collection failed: $WinRMError"

                Write-Verbose `
                    "[$Computer] Attempting Windows Features collection through WMI/DCOM."
            }

            # ========================================================
            # 2. WMI / DCOM fallback
            # ========================================================

            try {

                $CimResult = & (Get-Module TechHub.ActiveDirectory) {

                    Invoke-AssessmentADRemoteCimQuery `
                        -ComputerName $Computer `
                        -Credential $Credential `
                        -ScriptBlock {

                            param(
                                $Session
                            )

                            Get-CimInstance `
                                -CimSession $Session `
                                -ClassName Win32_OptionalFeature `
                                -ErrorAction Stop |
                            Where-Object {
                                $_.InstallState -eq 1
                            } |
                            Select-Object `
                                Name,
                                Caption,
                                InstallState
                        }
                }

                if (
                    $null -eq $CimResult -or
                    $CimResult.Status -ne 'Available'
                ) {

                    $ErrorMessage = $null

                    if ($null -ne $CimResult) {
                        $ErrorMessage = $CimResult.ErrorMessage
                    }

                    [PSCustomObject][ordered]@{
                        ComputerName     = $Computer
                        FeatureName      = $null
                        Status           = 'NotAvailable'
                        DataAvailability = 'NotAvailable'
                        CollectionMethod = 'None'
                        ErrorType        = 'RemoteTransportUnavailable'
                        ErrorMessage     = $ErrorMessage
                        IsReadOnly       = $true
                    }

                    continue
                }

                Write-Verbose `
                    "[$Computer] Windows Features collected through WMI/DCOM."

                $Features = @(
                    $CimResult.Data
                )

                if ($Features.Count -eq 0) {

                    [PSCustomObject][ordered]@{
                        ComputerName     = $Computer
                        FeatureName      = $null
                        Status           = 'Available'
                        DataAvailability = 'Available'
                        CollectionMethod = 'WMI'
                        ErrorType        = $null
                        ErrorMessage     = $null
                        IsReadOnly       = $true
                    }

                    continue
                }

                foreach ($Feature in $Features) {

                    if (
                        $null -eq $Feature -or
                        [string]::IsNullOrWhiteSpace(
                            [string]$Feature.Name
                        )
                    ) {
                        continue
                    }

                    [PSCustomObject][ordered]@{
                        ComputerName     = $Computer
                        FeatureName      = [string]$Feature.Name
                        Status           = 'Available'
                        DataAvailability = 'Available'
                        CollectionMethod = 'WMI'
                        ErrorType        = $null
                        ErrorMessage     = $null
                        IsReadOnly       = $true
                    }
                }
            }
            catch {

                $DCOMError = $_.Exception.Message

                Write-Verbose `
                    "[$Computer] WMI/DCOM collection failed: $DCOMError"

                [PSCustomObject][ordered]@{
                    ComputerName     = $Computer
                    FeatureName      = $null
                    Status           = 'NotAvailable'
                    DataAvailability = 'NotAvailable'
                    CollectionMethod = 'None'
                    ErrorType        = 'RemoteTransportUnavailable'
                    ErrorMessage     = $DCOMError
                    IsReadOnly       = $true
                }
            }
        }
    }
}