#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-TechHubADRemoteWindowsFeatures {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Computer','CN','Name')]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        try {

            $invokeParams = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    $featureNames = @()

                    $serverManagerAvailable = @(
                        Get-Module -ListAvailable -Name ServerManager
                    ).Count -gt 0

                    if ($serverManagerAvailable) {

                        Import-Module ServerManager `
                            -ErrorAction SilentlyContinue

                        $featureNames = @(
                            Get-WindowsFeature |
                            Where-Object { $_.Installed } |
                            Select-Object -ExpandProperty Name
                        )
                    }

                    if (-not $featureNames) {

                        $os = Get-CimInstance `
                            -ClassName Win32_OperatingSystem `
                            -ErrorAction Stop

                        if ($os.ProductType -eq 1) {

                            try {
                                $featureNames = @(
                                    Get-WindowsOptionalFeature `
                                        -Online `
                                        -ErrorAction Stop |
                                    Where-Object { $_.State -eq 'Enabled' } |
                                    Select-Object -ExpandProperty FeatureName
                                )
                            }
                            catch {
                                $lines = & dism.exe `
                                    /online `
                                    /Get-Features `
                                    /Format:Table 2>$null

                                $featureNames = @(
                                    $lines |
                                    Where-Object {
                                        $_ -match '^\S+\s+Enabled\s*$'
                                    } |
                                    ForEach-Object {
                                        ($_ -split '\s+')[0]
                                    }
                                )
                            }
                        }
                        else {

                            $lines = & dism.exe `
                                /online `
                                /Get-Features `
                                /Format:Table 2>$null

                            $featureNames = @(
                                $lines |
                                Where-Object {
                                    $_ -match '^\S+\s+Enabled\s*$'
                                } |
                                ForEach-Object {
                                    ($_ -split '\s+')[0]
                                }
                            )
                        }
                    }

                    foreach ($feature in $featureNames) {

                        if (
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$feature
                            )
                        ) {
                            [PSCustomObject][ordered]@{
                                ComputerName = $env:COMPUTERNAME
                                FeatureName  = [string]$feature
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

            Invoke-Command @invokeParams
        }
        catch {
            Write-Error `
                -Message "[$ComputerName] Remote query failed: $($_.Exception.Message)"
        }
    }
}