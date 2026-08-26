#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Export-AssessmentADAssessmentCsv' {

    BeforeAll {
        . "$PSScriptRoot\..\Classes\TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\New-AssessmentADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\Export-AssessmentADAssessmentCsv.ps1"
    }

    It 'writes an assessment CSV' {

        $Assessment = New-AssessmentADAssessmentResult

        $Assessment.AddInventory(
            [PSCustomObject][ordered]@{
                ComputerName = 'TEST01'
                Collector    = 'ServiceAccounts'
                Data         = [PSCustomObject]@{
                    ServiceName = 'TestService'
                    AccountName = 'DOMAIN\TestAccount'
                }
                Status       = 'Success'
                Error        = $null
                IsReadOnly   = $true
            }
        )

        $Path = Join-Path $TestDrive 'assessment.csv'

        $File = Export-AssessmentADAssessmentCsv `
            -Assessment $Assessment `
            -Path $Path

        Test-Path -LiteralPath $Path |
            Should -BeTrue

        $File.Name |
            Should -Be 'assessment.csv'
    }

    It 'exports inventory records' {

        $Assessment = New-AssessmentADAssessmentResult

        $Assessment.AddInventory(
            [PSCustomObject][ordered]@{
                ComputerName = 'TEST01'
                Collector    = 'ServiceAccounts'
                Data         = [PSCustomObject]@{
                    ServiceName = 'TestService'
                    AccountName = 'DOMAIN\TestAccount'
                }
                Status       = 'Success'
                Error        = $null
                IsReadOnly   = $true
            }
        )

        $Path = Join-Path $TestDrive 'inventory.csv'

        Export-AssessmentADAssessmentCsv `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Rows = @(Import-Csv -LiteralPath $Path)

        $Rows.Count |
            Should -Be 1

        $Rows[0].RecordType |
            Should -Be 'Inventory'

        $Rows[0].Collector |
            Should -Be 'ServiceAccounts'

        $Rows[0].ComputerName |
            Should -Be 'TEST01'
    }

    It 'exports findings' {

        $Assessment = New-AssessmentADAssessmentResult

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

        $Path = Join-Path $TestDrive 'findings.csv'

        Export-AssessmentADAssessmentCsv `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Rows = @(Import-Csv -LiteralPath $Path)

        $Rows.Count |
            Should -Be 1

        $Rows[0].RecordType |
            Should -Be 'Finding'

        $Rows[0].CheckId |
            Should -Be 'TEST-CHECK'

        $Rows[0].Severity |
            Should -Be 'High'
    }

    It 'creates the destination directory' {

        $Assessment = New-AssessmentADAssessmentResult

        $Path = Join-Path `
            $TestDrive `
            'output\assessment.csv'

        Export-AssessmentADAssessmentCsv `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        Test-Path -LiteralPath $Path |
            Should -BeTrue
    }

    It 'does not modify the assessment' {

        $Assessment = New-AssessmentADAssessmentResult

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

        $Path = Join-Path $TestDrive 'assessment.csv'

        Export-AssessmentADAssessmentCsv `
            -Assessment $Assessment `
            -Path $Path |
            Out-Null

        $Assessment.AssessmentId |
            Should -Be $BeforeId

        $Assessment.Inventory.Count |
            Should -Be $BeforeCount
    }
}