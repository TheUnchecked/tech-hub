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

    .PARAMETER ComputerName
        Target computer. Supports pipeline input.

    .PARAMETER Collector
        One or more of: ServiceAccounts, ScheduledTasks, IISAppPools,
        LocalGroups, NetworkShares, OSInfo, WindowsFeatures, UserRights.
        Runs all of them by default.

    .PARAMETER Credential
        Optional alternate credential, forwarded to collectors that support it.

    .OUTPUTS
        The combined objects from each collector, each with an added Collector
        property. A collector that fails outright for a computer emits one
        record with Status = 'Error' and the failure message instead of data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Computer', 'CN', 'Name')]
        [string]$ComputerName,

        [Parameter()]
        [string[]]$Collector,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

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

            try {
                $Command = Get-Command -Name $FunctionName -CommandType Function -ErrorAction Stop

                $Parameters = @{ ComputerName = $ComputerName }

                if ($null -ne $Credential -and $Command.Parameters.ContainsKey('Credential')) {
                    $Parameters.Credential = $Credential
                }

                $Results = @(& $Command @Parameters -ErrorAction Stop)

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
        }
    }
}
