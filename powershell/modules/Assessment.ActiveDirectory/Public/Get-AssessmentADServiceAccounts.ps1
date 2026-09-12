#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADServiceAccounts {
    <#
    .SYNOPSIS
        Inventories service-related execution accounts on remote Windows computers.

    .DESCRIPTION
        Read-only remote assessment of accounts used by:
        - Windows Services
        - Scheduled Tasks
        - IIS Application Pools

        The function normalizes the result into a common contract so the
        different execution mechanisms can be assessed together.

    .PARAMETER ComputerName
        One or more remote Windows computers.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        PSCustomObject with:
        ComputerName
        SourceType
        SourceName
        AccountName
        Status
        IsReadOnly

    .NOTES
        Read-only.
        No configuration changes are performed.
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            Position = 0
        )]
        [Alias('Computer', 'CN', 'Hostname', 'Name')]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {

        function ConvertTo-AssessmentAccountName {
            param(
                [AllowNull()]
                [AllowEmptyString()]
                [string]$Identity,

                [string]$TargetComputer
            )

            if ([string]::IsNullOrWhiteSpace($Identity)) {
                return $null
            }

            switch -Regex ($Identity) {

                '^(?i)LocalSystem$' {
                    return 'NT AUTHORITY\SYSTEM'
                }

                '^(?i)SYSTEM$' {
                    return 'NT AUTHORITY\SYSTEM'
                }

                '^(?i)LocalService$' {
                    return 'NT AUTHORITY\LOCAL SERVICE'
                }

                '^(?i)NetworkService$' {
                    return 'NT AUTHORITY\NETWORK SERVICE'
                }

                '^[.]\\' {
                    return ($Identity -replace '^[.]\\', "$TargetComputer\")
                }

                default {
                    return $Identity
                }
            }
        }

        function New-AssessmentServiceAccountRecord {
            param(
                [string]$Computer,
                [string]$SourceType,
                [string]$SourceName,
                [string]$AccountName,
                [string]$Status = 'Available'
            )

            [PSCustomObject][ordered]@{
                ComputerName = $Computer
                SourceType   = $SourceType
                SourceName   = $SourceName
                AccountName  = $AccountName
                Status       = $Status
                IsReadOnly   = $true
            }
        }

        function Get-AssessmentRemoteData {
            param(
                [string]$Computer,
                [hashtable]$InvokeParameters
            )

            Invoke-Command @InvokeParameters
        }
    }

    process {

        foreach ($Computer in $ComputerName) {

            $icmParams = @{
                ComputerName = $Computer
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    param($TargetComputer)

                    $records = @()

                    # ---------------------------------------------------------
                    # Windows Services
                    # ---------------------------------------------------------

                    try {

                        $services = Get-CimInstance `
                            -ClassName Win32_Service `
                            -ErrorAction Stop

                        foreach ($service in @($services)) {

                            $account = $service.StartName

                            if ([string]::IsNullOrWhiteSpace($account)) {
                                continue
                            }

                            if ($account -match '^[.]\\') {
                                $account = $account -replace '^[.]\\', "$TargetComputer\"
                            }
                            elseif ($account -match '^(?i)LocalSystem$') {
                                $account = 'NT AUTHORITY\SYSTEM'
                            }
                            elseif ($account -match '^(?i)SYSTEM$') {
                                $account = 'NT AUTHORITY\SYSTEM'
                            }
                            elseif ($account -match '^(?i)LocalService$') {
                                $account = 'NT AUTHORITY\LOCAL SERVICE'
                            }
                            elseif ($account -match '^(?i)NetworkService$') {
                                $account = 'NT AUTHORITY\NETWORK SERVICE'
                            }

                            $records += [PSCustomObject]@{
                                SourceType  = 'Service'
                                SourceName  = $service.Name
                                AccountName = $account
                            }
                        }

                    }
                    catch {
                        $records += [PSCustomObject]@{
                            SourceType  = 'Service'
                            SourceName  = $null
                            AccountName = $null
                            Status      = 'Error'
                            Error       = $_.Exception.Message
                        }
                    }

                    # ---------------------------------------------------------
                    # Scheduled Tasks
                    # ---------------------------------------------------------

                    try {

                        $tasks = Get-ScheduledTask -ErrorAction Stop

                        foreach ($task in @($tasks)) {

                            $account = $null

                            try {
                                $account = $task.Principal.UserId
                            }
                            catch {
                            }

                            if ([string]::IsNullOrWhiteSpace($account)) {
                                try {
                                    $account = $task.Principal.GroupId
                                }
                                catch {
                                }
                            }

                            if (-not [string]::IsNullOrWhiteSpace($account)) {

                                if ($account -match '^(?i)SYSTEM$') {
                                    $account = 'NT AUTHORITY\SYSTEM'
                                }
                                elseif ($account -match '^(?i)LOCAL SERVICE$') {
                                    $account = 'NT AUTHORITY\LOCAL SERVICE'
                                }
                                elseif ($account -match '^(?i)NETWORK SERVICE$') {
                                    $account = 'NT AUTHORITY\NETWORK SERVICE'
                                }
                                elseif ($account -match '^[.]\\') {
                                    $account = $account -replace '^[.]\\', "$TargetComputer\"
                                }
                            }

                            $taskPath = '{0}{1}' -f `
                                $task.TaskPath, `
                                $task.TaskName

                            $records += [PSCustomObject]@{
                                SourceType  = 'ScheduledTask'
                                SourceName  = $taskPath
                                AccountName = $account
                            }
                        }

                    }
                    catch {
                        $records += [PSCustomObject]@{
                            SourceType  = 'ScheduledTask'
                            SourceName  = $null
                            AccountName = $null
                            Status      = 'Error'
                            Error       = $_.Exception.Message
                        }
                    }

                    # ---------------------------------------------------------
                    # IIS Application Pools
                    # ---------------------------------------------------------

                    try {

                        Add-Type `
                            -AssemblyName 'Microsoft.Web.Administration' `
                            -ErrorAction Stop

                        $serverManager = New-Object `
                            Microsoft.Web.Administration.ServerManager

                        foreach ($pool in $serverManager.ApplicationPools) {

                            $identityType = $pool.ProcessModel.IdentityType.ToString()
                            $account = $null

                            switch ($identityType) {

                                'ApplicationPoolIdentity' {
                                    $account = "IIS APPPOOL\$($pool.Name)"
                                }

                                'LocalSystem' {
                                    $account = 'NT AUTHORITY\SYSTEM'
                                }

                                'LocalService' {
                                    $account = 'NT AUTHORITY\LOCAL SERVICE'
                                }

                                'NetworkService' {
                                    $account = 'NT AUTHORITY\NETWORK SERVICE'
                                }

                                'SpecificUser' {
                                    $account = $pool.ProcessModel.UserName
                                }

                                default {
                                    $account = $pool.ProcessModel.UserName
                                }
                            }

                            $records += [PSCustomObject]@{
                                SourceType  = 'IISAppPool'
                                SourceName  = $pool.Name
                                AccountName = $account
                            }
                        }

                    }
                    catch {
                        # IIS is optional. Absence of IIS is therefore not an
                        # assessment failure.
                    }

                    foreach ($record in @($records)) {

                        if ($record.PSObject.Properties['Status']) {
                            $status = $record.Status
                        }
                        else {
                            $status = 'Available'
                        }

                        [PSCustomObject][ordered]@{
                            ComputerName = $TargetComputer
                            SourceType   = $record.SourceType
                            SourceName   = $record.SourceName
                            AccountName  = $record.AccountName
                            Status       = $status
                            IsReadOnly   = $true
                        }
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $icmParams.Credential = $Credential
            }

            try {
                Get-AssessmentRemoteData `
                    -Computer $Computer `
                    -InvokeParameters $icmParams
            }
            catch {
                Write-Error `
                    -Message "[$Computer] Remote query failed: $($_.Exception.Message)"
            }
        }
    }
}