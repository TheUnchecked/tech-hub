#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'TechHub Active Directory Remote Assessment contract' {

    BeforeAll {
        . "$PSScriptRoot\..\..\Classes\TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\..\Public\New-TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\..\Public\Invoke-TechHubADRemoteAssessment.ps1"

        function Get-TechHubADServiceAccounts {
            param(
                [string]$ComputerName
            )

            [PSCustomObject]@{
                ComputerName = $ComputerName
                ServiceName  = 'TestService'
                AccountName  = 'DOMAIN\TestAccount'
                IsReadOnly   = $true
            }
        }
    }

    It 'returns a TechHubADAssessmentResult' {

        $result = Invoke-TechHubADRemoteAssessment `
            -ComputerName 'TEST01' `
            -Collector ServiceAccounts

        $result.GetType().Name |
            Should -Be 'TechHubADAssessmentResult'
    }

    It 'stores remote collector results in Inventory' {

        $result = Invoke-TechHubADRemoteAssessment `
            -ComputerName 'TEST01' `
            -Collector ServiceAccounts

        $result.Inventory.Count |
            Should -Be 1

        $result.Summary.InventoryCount |
            Should -Be 1
    }

    It 'preserves the collector identity' {

        $result = Invoke-TechHubADRemoteAssessment `
            -ComputerName 'TEST01' `
            -Collector ServiceAccounts

        $result.Inventory[0].Collector |
            Should -Be 'ServiceAccounts'
    }

    It 'preserves the source computer name' {

        $result = Invoke-TechHubADRemoteAssessment `
            -ComputerName 'TEST01' `
            -Collector ServiceAccounts

        $result.Inventory[0].ComputerName |
            Should -Be 'TEST01'
    }

    It 'marks remote assessment data as read-only' {

        $result = Invoke-TechHubADRemoteAssessment `
            -ComputerName 'TEST01' `
            -Collector ServiceAccounts

        $result.Inventory[0].IsReadOnly |
            Should -BeTrue
    }
}