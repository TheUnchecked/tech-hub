#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteWindowsFeatures' {

    BeforeAll {
        . "$PSScriptRoot\TechHubADRemoteCimTestStubs.ps1"
        . "$PSScriptRoot\..\Private\Invoke-AssessmentADRemoteCimQuery.ps1"
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteWindowsFeatures.ps1"
    }

    It 'returns installed features' {

        Mock Invoke-Command {
            @(
                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    FeatureName  = 'Web-Server'
                    Status       = 'Installed'
                    IsReadOnly   = $true
                }

                [PSCustomObject]@{
                    ComputerName = 'WEB01'
                    FeatureName  = 'DNS'
                    Status       = 'Installed'
                    IsReadOnly   = $true
                }
            )
        }

        $result = @(
            Get-AssessmentADRemoteWindowsFeatures -ComputerName 'WEB01'
        )

        $result.Count | Should -Be 2
        $result.FeatureName | Should -Contain 'Web-Server'
        $result.FeatureName | Should -Contain 'DNS'
    }

    It 'supports multiple computers' {

        Mock Invoke-Command {
            [PSCustomObject]@{
                ComputerName = 'WEB01'
                FeatureName  = 'Web-Server'
                Status       = 'Installed'
                IsReadOnly   = $true
            }
        }

        $result = @(
            'WEB01','WEB02' |
            Get-AssessmentADRemoteWindowsFeatures
        )

        $result.Count | Should -Be 2
    }

    It 'supports alternate credentials' {

        Mock Invoke-Command {
            [PSCustomObject]@{
                ComputerName = 'WEB01'
                FeatureName  = 'DNS'
                Status       = 'Installed'
                IsReadOnly   = $true
            }
        }

        $credential = New-Object `
            System.Management.Automation.PSCredential(
                'TEST\User',
                (ConvertTo-SecureString `
                    'Password123!' `
                    -AsPlainText `
                    -Force)
            )

        Get-AssessmentADRemoteWindowsFeatures `
            -ComputerName 'WEB01' `
            -Credential $credential |
            Out-Null

        Should -Invoke Invoke-Command -Times 1 -Exactly
    }

    It 'handles remote failure' {

        Mock Invoke-Command {
            throw 'Synthetic remote failure'
        }

        Mock New-CimSession {
            throw 'Synthetic WSMan failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $result = @(
            Get-AssessmentADRemoteWindowsFeatures -ComputerName 'WEB01'
        )

        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'WEB01'
        $result[0].Status | Should -Be 'NotAvailable'
        $result[0].DataAvailability | Should -Be 'NotAvailable'
        $result[0].ErrorType | Should -Be 'RemoteTransportUnavailable'
        $result[0].ErrorMessage | Should -Not -BeNullOrEmpty
        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'returns read-only records' {

        Mock Invoke-Command {
            [PSCustomObject]@{
                ComputerName = 'WEB01'
                FeatureName  = 'DNS'
                Status       = 'Installed'
                IsReadOnly   = $true
            }
        }

        $result = @(
            Get-AssessmentADRemoteWindowsFeatures -ComputerName 'WEB01'
        )

        $result[0].ComputerName | Should -Be 'WEB01'
        $result[0].FeatureName | Should -Be 'DNS'
        $result[0].Status | Should -Be 'Available'
        $result[0].DataAvailability | Should -Be 'Available'
        $result[0].CollectionMethod | Should -Be 'WinRM'
        $result[0].IsReadOnly | Should -BeTrue
    }
}