#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteOSInfo' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteOSInfo.ps1"
    }

    It 'returns OS information' {

        Mock Invoke-Command {
            [PSCustomObject][ordered]@{
                ComputerName            = 'WEB01'
                OSCaption               = 'Microsoft Windows Server 2022 Standard'
                OSVersion               = '10.0.20348'
                OSBuildNumber           = 20348
                OSSKU                   = 20348
                WindowsInstallationType = 'Server'
                Status                  = 'Available'
                IsReadOnly              = $true
            }
        }

        $result = @(Get-AssessmentADRemoteOSInfo -ComputerName 'WEB01')

        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'WEB01'
        $result[0].OSCaption | Should -Be 'Microsoft Windows Server 2022 Standard'
        $result[0].OSVersion | Should -Be '10.0.20348'
        $result[0].OSBuildNumber | Should -Be 20348
        $result[0].WindowsInstallationType | Should -Be 'Server'
        $result[0].Status | Should -Be 'Available'
        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'supports multiple computers' {

        Mock Invoke-Command {
            [PSCustomObject][ordered]@{
                ComputerName            = 'WEB01'
                OSCaption               = 'Windows Server'
                OSVersion               = '10.0'
                OSBuildNumber           = 20348
                OSSKU                   = 20348
                WindowsInstallationType = 'Server'
                Status                  = 'Available'
                IsReadOnly              = $true
            }
        }

        $result = @(
            Get-AssessmentADRemoteOSInfo -ComputerName 'WEB01','WEB02'
        )

        $result.Count | Should -Be 2
    }

    It 'supports UseSSL' {

        Mock Invoke-Command {
            [PSCustomObject][ordered]@{
                ComputerName            = 'WEB01'
                OSCaption               = 'Windows Server'
                OSVersion               = '10.0'
                OSBuildNumber           = 20348
                OSSKU                   = 20348
                WindowsInstallationType = 'Server'
                Status                  = 'Available'
                IsReadOnly              = $true
            }
        }

        Get-AssessmentADRemoteOSInfo `
            -ComputerName 'WEB01' `
            -UseSSL |
            Out-Null

        Should -Invoke Invoke-Command -Times 1 -Exactly
    }

    It 'handles a remote query failure' {

        Mock Invoke-Command {
            throw 'Synthetic remote failure'
        }

        $errorRecord = $null

        $result = @(
            Get-AssessmentADRemoteOSInfo `
                -ComputerName 'WEB01' `
                -ErrorVariable errorRecord `
                -ErrorAction SilentlyContinue
        )

        $result.Count | Should -Be 0
        @($errorRecord).Count | Should -BeGreaterThan 0
    }

    It 'has the expected read-only contract' {

        Mock Invoke-Command {
            [PSCustomObject][ordered]@{
                ComputerName            = 'WEB01'
                OSCaption               = 'Windows Server'
                OSVersion               = '10.0'
                OSBuildNumber           = 20348
                OSSKU                   = 20348
                WindowsInstallationType = 'Server'
                Status                  = 'Available'
                IsReadOnly              = $true
            }
        }

        $result = @(Get-AssessmentADRemoteOSInfo -ComputerName 'WEB01')

        $result[0].PSObject.Properties.Name |
            Should -Contain 'ComputerName'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'OSCaption'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'OSVersion'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'OSBuildNumber'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'Status'

        $result[0].PSObject.Properties.Name |
            Should -Contain 'IsReadOnly'

        $result[0].IsReadOnly | Should -BeTrue
    }
}