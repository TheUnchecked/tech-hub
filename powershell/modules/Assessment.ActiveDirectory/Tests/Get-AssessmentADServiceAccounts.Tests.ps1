#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADServiceAccounts' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-AssessmentADServiceAccounts.ps1"
    }

    It 'returns normalized service accounts' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'Service'
                    SourceName   = 'MyService'
                    AccountName  = 'CONTOSO\svc-web'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }
            )
        }

        $result = @(Get-AssessmentADServiceAccounts -ComputerName 'WEB01')

        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'WEB01'
        $result[0].SourceType | Should -Be 'Service'
        $result[0].SourceName | Should -Be 'MyService'
        $result[0].AccountName | Should -Be 'CONTOSO\svc-web'
        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'supports multiple computers' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = $ComputerName
                    SourceType   = 'Service'
                    SourceName   = 'Svc01'
                    AccountName  = 'CONTOSO\svc01'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }
            )
        }

        $result = @(
            Get-AssessmentADServiceAccounts -ComputerName 'WEB01','WEB02'
        )

        $result.Count | Should -Be 2
    }

    It 'returns the common assessment contract' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'Service'
                    SourceName   = 'Svc01'
                    AccountName  = 'CONTOSO\svc01'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }

                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'ScheduledTask'
                    SourceName   = '\Backup'
                    AccountName  = 'CONTOSO\svc-backup'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }

                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'IISAppPool'
                    SourceName   = 'MyAppPool'
                    AccountName  = 'IIS APPPOOL\MyAppPool'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }
            )
        }

        $result = @(Get-AssessmentADServiceAccounts -ComputerName 'WEB01')

        $result.Count | Should -Be 3

        @($result | Where-Object SourceType -eq 'Service').Count |
            Should -Be 1

        @($result | Where-Object SourceType -eq 'ScheduledTask').Count |
            Should -Be 1

        @($result | Where-Object SourceType -eq 'IISAppPool').Count |
            Should -Be 1

        $result[0].PSObject.Properties.Name |
            Should -Contain 'ComputerName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'SourceType'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'SourceName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'AccountName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'Status'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'IsReadOnly'
    }

    It 'is read-only' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'Service'
                    SourceName   = 'Svc01'
                    AccountName  = 'CONTOSO\svc01'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }
            )
        }

        {
            Get-AssessmentADServiceAccounts -ComputerName 'WEB01'
        } | Should -Not -Throw
    }

    It 'normalizes LocalSystem' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    SourceType   = 'Service'
                    SourceName   = 'Svc01'
                    AccountName  = 'NT AUTHORITY\SYSTEM'
                    Status       = 'Available'
                    IsReadOnly   = $true
                }
            )
        }

        $result = @(Get-AssessmentADServiceAccounts -ComputerName 'WEB01')

        $result[0].AccountName |
            Should -Be 'NT AUTHORITY\SYSTEM'
    }
}