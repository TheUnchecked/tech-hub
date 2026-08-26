#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Export-AssessmentADAssessmentJson' {

    BeforeAll {
        . "$PSScriptRoot\..\Classes\TechHubADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\New-AssessmentADAssessmentResult.ps1"
        . "$PSScriptRoot\..\Public\Export-AssessmentADAssessmentJson.ps1"
    }

    It 'returns JSON when no path is specified' {

        $Assessment = New-AssessmentADAssessmentResult

        $Json = Export-AssessmentADAssessmentJson `
            -Assessment $Assessment

        $Json | Should -Not -BeNullOrEmpty

        {
            $Json | ConvertFrom-Json
        } | Should -Not -Throw
    }

    It 'contains the assessment identity' {

        $Assessment = New-AssessmentADAssessmentResult

        $Json = Export-AssessmentADAssessmentJson `
            -Assessment $Assessment

        $Object = $Json | ConvertFrom-Json

        $Object.AssessmentId |
            Should -Be $Assessment.AssessmentId.ToString()
    }

    It 'serializes inventory data' {

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

        $Json = Export-AssessmentADAssessmentJson `
            -Assessment $Assessment

        $Object = $Json | ConvertFrom-Json

        $Object.Inventory.Count |
            Should -Be 1

        $Object.Inventory[0].Collector |
            Should -Be 'ServiceAccounts'

        $Object.Inventory[0].Data.AccountName |
            Should -Be 'DOMAIN\TestAccount'
    }

    It 'writes JSON to a file' {

        $Assessment = New-AssessmentADAssessmentResult

        $Path = Join-Path `
            $TestDrive `
            'assessment.json'

        $File = Export-AssessmentADAssessmentJson `
            -Assessment $Assessment `
            -Path $Path

        Test-Path -LiteralPath $Path |
            Should -BeTrue

        $File.Name |
            Should -Be 'assessment.json'

        $Content = Get-Content `
            -LiteralPath $Path `
            -Raw

        $Content | Should -Not -BeNullOrEmpty

        {
            $Content | ConvertFrom-Json
        } | Should -Not -Throw
    }

    It 'does not modify the assessment' {

        $Assessment = New-AssessmentADAssessmentResult

        $BeforeId = $Assessment.AssessmentId
        $BeforeCount = $Assessment.Inventory.Count

        Export-AssessmentADAssessmentJson `
            -Assessment $Assessment |
            Out-Null

        $Assessment.AssessmentId |
            Should -Be $BeforeId

        $Assessment.Inventory.Count |
            Should -Be $BeforeCount
    }
}