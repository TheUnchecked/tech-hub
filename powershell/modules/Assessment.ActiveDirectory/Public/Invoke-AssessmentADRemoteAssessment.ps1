#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteAssessment {
    <#
    .SYNOPSIS
        Runs one or more remote infrastructure collectors against a computer.

    .DESCRIPTION
        Dispatches to the selected Get-AssessmentADRemote* collectors and
        returns their combined results, each record tagged with the
        Collector name that produced it.

        Each collector call runs in a background job with a hard wall-clock
        timeout (TimeoutSeconds). The reachability checks in the underlying
        transports only bound the initial connection attempt; they cannot
        bound a hang that happens after the connection succeeds (a stuck
        secedit.exe, a WMI call that never returns, and so on). Running the
        call as a job means it can always be stopped and removed once the
        timeout elapses, regardless of where it is stuck, so one bad host
        never holds up the whole assessment.

    .PARAMETER ComputerName
        Target computer. Supports pipeline input.

    .PARAMETER Collector
        One or more of: ServiceAccounts, ScheduledTasks, IISAppPools,
        LocalGroups, NetworkShares, OSInfo, WindowsFeatures, UserRights.
        Runs all of them by default.

    .PARAMETER Credential
        Optional alternate credential, forwarded to collectors that support it.

    .PARAMETER TimeoutSeconds
        Maximum time allowed for each collector call against each computer,
        in seconds. Default 60. A collector that does not finish in time is
        stopped and reported with Status = 'Timeout'.

    .OUTPUTS
        The combined objects from each collector, each with an added Collector
        property. A collector that fails outright for a computer emits one
        record with Status = 'Error' and the failure message instead of data.
        A collector that exceeds TimeoutSeconds emits one record with
        Status = 'Timeout'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Computer', 'CN', 'Name')]
        [string]$ComputerName,

        [Parameter()]
        [string[]]$Collector,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [int]$TimeoutSeconds = 60
    )

    begin {

        $ModulePath = (Get-Module -Name Assessment.ActiveDirectory | Select-Object -First 1).Path

        if ([string]::IsNullOrWhiteSpace($ModulePath)) {
            throw 'Unable to resolve the path of the Assessment.ActiveDirectory module. Import it with Import-Module before calling Invoke-AssessmentADRemoteAssessment.'
        }
    }

    process {

        $CollectorMap = [ordered]@{
            ServiceAccounts = 'Get-AssessmentADRemoteServiceAccounts'
            ScheduledTasks  = 'Get-AssessmentADRemoteScheduledTaskAccounts'
            IISAppPools     = 'Get-AssessmentADRemoteIISAppPoolAccounts'
            LocalGroups     = 'Get-AssessmentADRemoteLocalGroups'
            NetworkShares   = 'Get-AssessmentADRemoteNetworkShareACLs'
            OSInfo          = 'Get-AssessmentADRemoteOSInfo'
            WindowsFeatures = 'Get-AssessmentADRemoteWindowsFeatures'
            UserRights      = 'Get-AssessmentADRemoteUserRightAssignments'
        }

        $SelectedCollectors = if ($PSBoundParameters.ContainsKey('Collector')) {
            @($Collector | Where-Object { $CollectorMap.Contains($_) })
        }
        else {
            @($CollectorMap.Keys)
        }

        foreach ($CollectorName in $SelectedCollectors) {

            $FunctionName = $CollectorMap[$CollectorName]

            Write-Verbose "[$ComputerName] Running collector $CollectorName (timeout ${TimeoutSeconds}s)."

            $Job = $null

            try {
                $Command = Get-Command -Name $FunctionName -CommandType Function -ErrorAction Stop

                $Parameters = @{ ComputerName = $ComputerName }

                if ($null -ne $Credential -and $Command.Parameters.ContainsKey('Credential')) {
                    $Parameters.Credential = $Credential
                }

                $Job = Start-Job -ScriptBlock {
                    param($JobModulePath, $JobFunctionName, $JobParameters)

                    Import-Module -Name $JobModulePath -Force -ErrorAction Stop

                    & $JobFunctionName @JobParameters -ErrorAction Stop
                } -ArgumentList $ModulePath, $FunctionName, $Parameters

                $Completed = Wait-Job -Job $Job -Timeout $TimeoutSeconds

                if ($null -eq $Completed) {

                    Write-Verbose "[$ComputerName] Collector $CollectorName exceeded ${TimeoutSeconds}s. Stopping it."

                    [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        Collector    = $CollectorName
                        Status       = 'Timeout'
                        Error        = "Collector did not complete within $TimeoutSeconds second(s)."
                    }

                    continue
                }

                $Results = @(Receive-Job -Job $Job -ErrorAction Stop)

                Write-Verbose "[$ComputerName] Collector $CollectorName completed."

                foreach ($Result in $Results) {

                    if ($null -eq $Result) { continue }

                    $Result | Add-Member -NotePropertyName Collector -NotePropertyValue $CollectorName -PassThru -Force
                }
            }
            catch {

                [PSCustomObject][ordered]@{
                    ComputerName = $ComputerName
                    Collector    = $CollectorName
                    Status       = 'Error'
                    Error        = $_.Exception.Message
                }
            }
            finally {

                if ($null -ne $Job) {
                    Stop-Job -Job $Job -ErrorAction SilentlyContinue
                    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
