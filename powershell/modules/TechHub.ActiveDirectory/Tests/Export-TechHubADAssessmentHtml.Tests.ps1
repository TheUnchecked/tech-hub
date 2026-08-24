#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Export-TechHubADAssessmentHtml' {

    BeforeAll {
        . "$PSScriptRoot\..\Classes\TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\New-TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\Export-TechHubADAssessmentHtml.ps1"
    }

    It 'writes an HTML assessment report' {

        $Assessment = New-TechHubADAssessmentResult

        $Path = Join-Path $TestDrive 'assessment.html'

        $File = Export-TechHubADAssessmentHtml `
            -Assessment $Assessment `
            -Path $Path

        Test-Path -LiteralPath $Path |
            Should -BeTrue

        $File.Name |
            Should -Be 'assessment.html'

        $Content = Get-Content `
            -LiteralPath $Path `
            -Raw

        $Content |
            Should -Match '<html'

        $Content |
            Should -Match '</html>'
    }

    It 'renders inventory records' {

        $Assessment = New-TechHubADAssessmentResult

        $Assessment.AddInventory(
            [PSCustomObject][ordered]@{
                ComputerName = 'TEST01'
                Collector    = 'ServiceAccounts'
                Data         = [PSCustomObject]@{
                    ServiceName = 'TestService'
                    AccountName = 'DOMAIN\TestAccount'
                }
                Status     = 'Success'
                Error      = $null
                IsReadOnly = $true
            }
        )

        $Path = Join-Path $TestDrive 'inventory.html'

        Export-TechHubADAssessmentHtml `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Content = Get-Content `
            -LiteralPath $Path `
            -Raw

        $Content |
            Should -Match 'TEST01'

        $Content |
            Should -Match 'ServiceAccounts'

        $Content |
            Should -Match 'TestService'
    }

    It 'renders findings' {

        $Assessment = New-TechHubADAssessmentResult

        $Assessment.AddFinding(
            [PSCustomObject][ordered]@{
                AssessmentId = $Assessment.AssessmentId
                CheckId      = 'TEST-CHECK'
                Title        = 'Test Finding'
                Severity     = 'High'
                Status       = 'Open'
                IsReadOnly   = $true
            }
        )

        $Path = Join-Path $TestDrive 'findings.html'

        Export-TechHubADAssessmentHtml `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Content = Get-Content `
            -LiteralPath $Path `
            -Raw

        $Content |
            Should -Match 'TEST-CHECK'

        $Content |
            Should -Match 'Test Finding'

        $Content |
            Should -Match 'High'
    }

    It 'creates the destination directory' {

        $Assessment = New-TechHubADAssessmentResult

        $Path = Join-Path `
            $TestDrive `
            'reports\assessment.html'

        Export-TechHubADAssessmentHtml `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        Test-Path -LiteralPath $Path |
            Should -BeTrue
    }

    It 'does not modify the assessment' {

        $Assessment = New-TechHubADAssessmentResult

        $Assessment.AddInventory(
            [PSCustomObject][ordered]@{
                ComputerName = 'TEST01'
                Collector    = 'OSInfo'
                Data         = [PSCustomObject]@{
                    OSName = 'Windows Server'
                }
                Status     = 'Success'
                Error      = $null
                IsReadOnly = $true
            }
        )

        $BeforeId = $Assessment.AssessmentId
        $BeforeCount = $Assessment.Inventory.Count

        $Path = Join-Path $TestDrive 'assessment.html'

        Export-TechHubADAssessmentHtml `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Assessment.AssessmentId |
            Should -Be $BeforeId

        $Assessment.Inventory.Count |
            Should -Be $BeforeCount
    }
}