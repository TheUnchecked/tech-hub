#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteIISAppPoolAccounts {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('CN','Name')]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        try {
            $InvokeParameters = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
                ScriptBlock  = {

                function Convert-AssessmentIISIdentity {
                    param(
                        [string]$UserName
                    )

                    if ([string]::IsNullOrWhiteSpace($UserName)) {
                        return $null
                    }

                    if ($UserName -match '\\') {
                        return $UserName
                    }

                    if ($UserName -like '*@*') {
                        try {
                            $nt = New-Object -ComObject NameTranslate
                            $nt.Init(3, $null)
                            $nt.Set(8, $UserName)

                            return $nt.Get(3)
                        }
                        catch {
                            return $UserName
                        }
                    }

                    try {
                        $local = [ADSI](
                            "WinNT://$env:COMPUTERNAME/$UserName,user"
                        )

                        if ($local.Name) {
                            return "$env:COMPUTERNAME\$UserName"
                        }
                    }
                    catch {}

                    try {
                        $nt = New-Object -ComObject NameTranslate
                        $nt.Init(3, $null)
                        $nt.Set(4, $UserName)

                        return $nt.Get(3)
                    }
                    catch {
                        return $UserName
                    }
                }

                $results = @()

                $serverManagerWorked = $false

                try {
                    Add-Type `
                        -AssemblyName 'Microsoft.Web.Administration' `
                        -ErrorAction Stop

                    $serverManager =
                        New-Object Microsoft.Web.Administration.ServerManager

                    foreach ($pool in $serverManager.ApplicationPools) {

                        $identityType =
                            $pool.ProcessModel.IdentityType.ToString()

                        $userName =
                            $pool.ProcessModel.UserName

                        $account = switch ($identityType) {

                            'ApplicationPoolIdentity' {
                                "IIS APPPOOL\$($pool.Name)"
                            }

                            'LocalSystem' {
                                'NT AUTHORITY\SYSTEM'
                            }

                            'LocalService' {
                                'NT AUTHORITY\LOCAL SERVICE'
                            }

                            'NetworkService' {
                                'NT AUTHORITY\NETWORK SERVICE'
                            }

                            'SpecificUser' {
                                Convert-AssessmentIISIdentity $userName
                            }

                            default {
                                $null
                            }
                        }

                        $results += [PSCustomObject][ordered]@{
                            ComputerName = $env:COMPUTERNAME
                            AppPoolName  = $pool.Name
                            AccountName  = $account
                            Status       = 'Available'
                            ErrorMessage = $null
                            IsReadOnly   = $true
                        }
                    }

                    $serverManagerWorked = $true
                }
                catch {}

                if (-not $serverManagerWorked) {

                    $path1 =
                        "$env:windir\System32\inetsrv\config\applicationHost.config"

                    $path2 =
                        "$env:windir\sysnative\inetsrv\config\applicationHost.config"

                    $configPath =
                        if (Test-Path $path1) {
                            $path1
                        }
                        else {
                            $path2
                        }

                    [xml]$config =
                        Get-Content -LiteralPath $configPath -ErrorAction Stop

                    $nodes =
                        $config.SelectNodes(
                            '/configuration/system.applicationHost/applicationPools/add'
                        )

                    foreach ($node in $nodes) {

                        $name =
                            $node.GetAttribute('name')

                        $processModel =
                            $node.SelectSingleNode('processModel')

                        $identityType =
                            $processModel.GetAttribute('identityType')

                        $userName =
                            $processModel.GetAttribute('userName')

                        $account = switch ($identityType) {

                            'ApplicationPoolIdentity' {
                                "IIS APPPOOL\$name"
                            }

                            'LocalSystem' {
                                'NT AUTHORITY\SYSTEM'
                            }

                            'LocalService' {
                                'NT AUTHORITY\LOCAL SERVICE'
                            }

                            'NetworkService' {
                                'NT AUTHORITY\NETWORK SERVICE'
                            }

                            'SpecificUser' {
                                Convert-AssessmentIISIdentity $userName
                            }

                            default {
                                $null
                            }
                        }

                        $results += [PSCustomObject][ordered]@{
                            ComputerName = $env:COMPUTERNAME
                            AppPoolName  = $name
                            AccountName  = $account
                            Status       = 'Available'
                            ErrorMessage = $null
                            IsReadOnly   = $true
                        }
                    }
                }

                $results
                }
            }

            if ($null -ne $Credential) {
                $InvokeParameters.Credential = $Credential
            }

            Invoke-Command @InvokeParameters
        }
        catch {

            [PSCustomObject][ordered]@{
                ComputerName = $ComputerName
                AppPoolName  = $null
                AccountName  = $null
                Status       = 'Error'
                ErrorMessage = $_.Exception.Message
                IsReadOnly   = $true
            }
        }
    }
}