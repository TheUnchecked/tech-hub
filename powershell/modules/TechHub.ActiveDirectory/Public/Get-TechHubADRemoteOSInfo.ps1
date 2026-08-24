#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-TechHubADRemoteOSInfo {
    <#
    .SYNOPSIS
        Collects operating system information from remote Windows computers.

    .DESCRIPTION
        Read-only remote assessment using PowerShell Remoting and WMI.
        Returns a normalized record for each target.

    .PARAMETER ComputerName
        One or more remote Windows computers.

    .PARAMETER Credential
        Optional alternate credential.

    .PARAMETER UseSSL
        Uses WinRM HTTPS.

    .OUTPUTS
        ComputerName
        OSCaption
        OSVersion
        OSBuildNumber
        OSSKU
        WindowsInstallationType
        Status
        IsReadOnly
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            Position = 0
        )]
        [Alias('CN','PSComputerName','Name','Computer')]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [switch]$UseSSL
    )

    process {
        foreach ($Computer in $ComputerName) {

            $invokeParams = @{
                ComputerName = $Computer
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    try {
                        $os = Get-CimInstance `
                            -ClassName Win32_OperatingSystem `
                            -ErrorAction Stop

                        $installationType = $null

                        try {
                            $reg = Get-ItemProperty `
                                -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                                -Name 'InstallationType' `
                                -ErrorAction Stop

                            $installationType = $reg.InstallationType
                        }
                        catch {
                            $installationType = $null
                        }

                        [PSCustomObject][ordered]@{
                            ComputerName            = $os.CSName
                            OSCaption               = $os.Caption
                            OSVersion               = $os.Version
                            OSBuildNumber           = [int]$os.BuildNumber
                            OSSKU                   = $os.OperatingSystemSKU
                            WindowsInstallationType = $installationType
                            Status                  = 'Available'
                            IsReadOnly              = $true
                        }
                    }
                    catch {
                        [PSCustomObject][ordered]@{
                            ComputerName            = $env:COMPUTERNAME
                            OSCaption               = $null
                            OSVersion               = $null
                            OSBuildNumber           = $null
                            OSSKU                   = $null
                            WindowsInstallationType = $null
                            Status                  = 'Error'
                            IsReadOnly              = $true
                        }
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParams.Credential = $Credential
            }

            if ($UseSSL) {
                $invokeParams.UseSSL = $true
            }

            try {
                Invoke-Command @invokeParams
            }
            catch {
                Write-Error `
                    -Message "[$Computer] Remote query failed: $($_.Exception.Message)"
            }
        }
    }
}