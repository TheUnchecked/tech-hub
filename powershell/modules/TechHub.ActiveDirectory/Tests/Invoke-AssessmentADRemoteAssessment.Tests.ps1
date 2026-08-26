#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Invoke-AssessmentADRemoteAssessment' {

    BeforeAll {

        . "$PSScriptRoot\..\Classes\TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\New-AssessmentADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\Invoke-AssessmentADRemoteAssessment.ps1"

        function Get-AssessmentADServiceAccounts {
            param([string]$ComputerName)

            [PSCustomObject]@{
                ComputerName = $ComputerName
                ServiceName  = 'TestService'
                AccountName  = 'DOMAIN\TestAccount'
                IsReadOnly   = $true
            }
        }

        function Get-AssessmentADRemoteScheduledTaskAccounts {
            param([string]$ComputerName)

            [PSCustomObject]@{
                ComputerName = $ComputerName
                TaskName     = '\TestTask'
                AccountName  = 'DOMAIN\TestAccount'
                IsReadOnly   = $true
            }
        }
    }

    It 'returns an AssessmentResult' {

        $result = Invoke-AssessmentADRemoteAssessment `
            -ComputerName 'WEB01' `
            -Collector ServiceAccounts

        $result | Should -Not -BeNullOrEmpty
        $result.GetType().Name | Should -Be 'TechHubADAssessmentResult'
    }

    It 'adds collector data to Inventory' {

        $result = Invoke-AssessmentADRemoteAssessment `
            -ComputerName 'WEB01' `
            -Collector ServiceAccounts

        $result.Inventory.Count | Should -Be 1

        $result.Inventory[0].Collector |
            Should -Be 'ServiceAccounts'

        $result.Inventory[0].Status |
            Should -Be 'Success'
    }

    It 'supports multiple collectors' {

        $result = Invoke-AssessmentADRemoteAssessment `
            -ComputerName 'WEB01' `
            -Collector ServiceAccounts,ScheduledTasks

        $result.Inventory.Count | Should -Be 2

        @($result.Inventory.Collector) |
            Should -Contain 'ServiceAccounts'

        @($result.Inventory.Collector) |
            Should -Contain 'ScheduledTasks'
    }

    It 'supports multiple computers through pipeline' {

        $results = @(
            'WEB01','WEB02' |
                Invoke-AssessmentADRemoteAssessment `
                    -Collector ServiceAccounts
        )

        $results.Count | Should -Be 2

        $results[0].Inventory.Count | Should -Be 1
        $results[1].Inventory.Count | Should -Be 1
    }

    It 'keeps collector records read-only' {

        $result = Invoke-AssessmentADRemoteAssessment `
            -ComputerName 'WEB01' `
            -Collector ServiceAccounts

        $result.Inventory[0].IsReadOnly |
            Should -BeTrue
    }
}