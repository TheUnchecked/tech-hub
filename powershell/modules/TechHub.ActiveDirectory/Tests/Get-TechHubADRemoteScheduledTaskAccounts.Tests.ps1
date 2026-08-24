#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-TechHubADRemoteScheduledTaskAccounts' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-TechHubADRemoteScheduledTaskAccounts.ps1"
    }

    It 'has the expected read-only contract' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-TechHubADRemoteScheduledTaskAccounts.ps1" `
            -Raw

        $content | Should -Match 'ComputerName'
        $content | Should -Match 'TaskName'
        $content | Should -Match 'AccountName'
        $content | Should -Match 'IsReadOnly'

        $content | Should -Not -Match '\bRegister-ScheduledTask\b'
        $content | Should -Not -Match '\bUnregister-ScheduledTask\b'
        $content | Should -Not -Match '\bSet-ScheduledTask\b'
        $content | Should -Not -Match '\bNew-ScheduledTask\b'
    }

    It 'supports pipeline input' {

        Mock New-CimSession {
            throw 'Synthetic CIM failure'
        }

        Mock New-Object {
            throw 'Synthetic COM failure'
        }

        $errors = @()

        @(
            'WEB01','WEB02' |
            Get-TechHubADRemoteScheduledTaskAccounts `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        ) | Should -HaveCount 0

        $errors.Count | Should -BeGreaterThan 0
    }

    It 'handles remote query failure' {

        Mock New-CimSession {
            throw 'Synthetic CIM failure'
        }

        Mock New-Object {
            throw 'Synthetic COM failure'
        }

        $errors = @()

        $result = @(
            Get-TechHubADRemoteScheduledTaskAccounts `
                -ComputerName 'WEB01' `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        )

        $result.Count | Should -Be 0
        $errors.Count | Should -BeGreaterThan 0
    }

    It 'contains CIM and COM collection paths' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-TechHubADRemoteScheduledTaskAccounts.ps1" `
            -Raw

        $content | Should -Match 'Get-ScheduledTask'
        $content | Should -Match 'Schedule.Service'
    }

    It 'normalizes well-known service accounts' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-TechHubADRemoteScheduledTaskAccounts.ps1" `
            -Raw

        $content | Should -Match 'NT AUTHORITY\\SYSTEM'
        $content | Should -Match 'NT AUTHORITY\\LOCAL SERVICE'
        $content | Should -Match 'NT AUTHORITY\\NETWORK SERVICE'
    }
}