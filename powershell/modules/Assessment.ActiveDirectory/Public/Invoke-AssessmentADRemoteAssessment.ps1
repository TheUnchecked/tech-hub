#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteAssessment {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Computer','CN','Name')]
        [string]$ComputerName,

        [Parameter()]
        [object]$Assessment,

        [Parameter()]
        [string[]]$Collector
    )

    process {

        # Create one AssessmentResult per computer when the
        # Assessment parameter is not explicitly supplied.
        $CurrentAssessment = $Assessment

        if ($null -eq $CurrentAssessment) {
            $CurrentAssessment = New-AssessmentADAssessmentResult
        }

        $CollectorMap = [ordered]@{
            ServiceAccounts = 'Get-AssessmentADServiceAccounts'
            ScheduledTasks  = 'Get-AssessmentADRemoteScheduledTaskAccounts'
            IISAppPools     = 'Get-AssessmentADRemoteIISAppPoolAccounts'
            LocalGroups     = 'Get-AssessmentADRemoteLocalGroupMembers'
            NetworkShares   = 'Get-AssessmentADRemoteNetworkShareACLs'
            OSInfo          = 'Get-AssessmentADRemoteOSInfo'
            WindowsFeatures = 'Get-AssessmentADRemoteWindowsFeatures'
        }

        $SelectedCollectors = @($CollectorMap.Keys)

        if ($PSBoundParameters.ContainsKey('Collector')) {
            $SelectedCollectors = @(
                $Collector |
                    Where-Object {
                        $CollectorMap.Contains($_)
                    }
            )
        }

        foreach ($CollectorName in $SelectedCollectors) {

            $FunctionName = $CollectorMap[$CollectorName]

            $BaseRecord = [ordered]@{
                ComputerName = $ComputerName
                Collector    = $CollectorName
                Data         = $null
                Status       = 'Error'
                Error        = $null
                IsReadOnly   = $true
            }

            try {

                $Command = Get-Command `
                    -Name $FunctionName `
                    -CommandType Function `
                    -ErrorAction Stop

                $Parameters = @{
                    ComputerName = $ComputerName
                }

                $Results = @(
                    & $Command @Parameters -ErrorAction Stop
                )

                foreach ($Result in $Results) {

                    $Record = [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        Collector    = $CollectorName
                        Data         = $Result
                        Status       = 'Success'
                        Error        = $null
                        IsReadOnly   = $true
                    }

                    $CurrentAssessment.AddInventory($Record)
                }

                if ($Results.Count -eq 0) {

                    $Record = [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        Collector    = $CollectorName
                        Data         = $null
                        Status       = 'Empty'
                        Error        = $null
                        IsReadOnly   = $true
                    }

                    $CurrentAssessment.AddInventory($Record)
                }
            }
            catch {

                $BaseRecord.Error = $_.Exception.Message

                $CurrentAssessment.AddInventory(
                    [PSCustomObject]$BaseRecord
                )
            }
        }

        $CurrentAssessment
    }
}