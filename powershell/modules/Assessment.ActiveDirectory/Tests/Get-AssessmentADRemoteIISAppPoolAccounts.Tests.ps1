#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteIISAppPoolAccounts' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteIISAppPoolAccounts.ps1"
    }

    It 'has the expected read-only contract' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteIISAppPoolAccounts.ps1" `
            -Raw

        $content | Should -Match 'ComputerName'
        $content | Should -Match 'AppPoolName'
        $content | Should -Match 'AccountName'
        $content | Should -Match 'IsReadOnly'

        $content | Should -Not -Match '\bSet-WebConfiguration\b'
        $content | Should -Not -Match '\bRemove-WebAppPool\b'
        $content | Should -Not -Match '\bNew-WebAppPool\b'
    }

    It 'supports pipeline input' {

        Mock Invoke-Command {
            throw 'Synthetic remote failure'
        }

        $errors = @()

        @(
            'WEB01','WEB02' |
            Get-AssessmentADRemoteIISAppPoolAccounts `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        ) | Should -HaveCount 0

        $errors.Count | Should -BeGreaterThan 0
    }

    It 'handles remote query failure' {

        Mock Invoke-Command {
            throw 'Synthetic connection failure'
        }

        $errors = @()

        $result = @(
            Get-AssessmentADRemoteIISAppPoolAccounts `
                -ComputerName 'WEB01' `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        )

        $result.Count | Should -Be 0
        $errors.Count | Should -BeGreaterThan 0
    }

    It 'contains the ServerManager collection path' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteIISAppPoolAccounts.ps1" `
            -Raw

        $content | Should -Match 'Microsoft.Web.Administration'
        $content | Should -Match 'ApplicationPools'
    }

    It 'contains the applicationHost.config fallback' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteIISAppPoolAccounts.ps1" `
            -Raw

        $content | Should -Match 'applicationHost.config'
        $content | Should -Match 'ApplicationPoolIdentity'
        $content | Should -Match 'SpecificUser'
    }
}