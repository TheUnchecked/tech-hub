#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteOSInfo' {

    BeforeAll {
        . "$PSScriptRoot\TechHubADRemoteCimTestStubs.ps1"
        . "$PSScriptRoot\..\Private\Invoke-AssessmentADRemoteCimQuery.ps1"
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteOSInfo.ps1"
    }

    It 'returns OS information' {

        Mock New-CimSession {
            [PSCustomObject]@{ Id = 'synthetic-session' }
        }

        Mock Get-CimInstance {
            [PSCustomObject]@{
                CSName             = 'WEB01'
                Caption            = 'Microsoft Windows Server 2022 Standard'
                Version            = '10.0.20348'
                BuildNumber        = 20348
                OperatingSystemSKU = 20348
                ProductType        = 3
            }
        }

        Mock Remove-CimSession {}

        $result = @(Get-AssessmentADRemoteOSInfo -ComputerName 'WEB01')

        $result.Count | Should -Be 1
        $result[0].ComputerName | Should -Be 'WEB01'
        $result[0].OSCaption | Should -Be 'Microsoft Windows Server 2022 Standard'
        $result[0].OSVersion | Should -Be '10.0.20348'
        $result[0].OSBuildNumber | Should -Be 20348
        $result[0].TargetType | Should -Be 'Server'
        $result[0].CollectionMethod | Should -Be 'WinRM'
        $result[0].Status | Should -Be 'Available'
        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'supports multiple computers' {

        Mock New-CimSession {
            [PSCustomObject]@{ Id = 'synthetic-session' }
        }

        Mock Get-CimInstance {
            [PSCustomObject]@{
                CSName             = 'WEB01'
                Caption            = 'Windows Server'
                Version            = '10.0'
                BuildNumber        = 20348
                OperatingSystemSKU = 20348
                ProductType        = 3
            }
        }

        Mock Remove-CimSession {}

        $result = @(
            'WEB01', 'WEB02' | Get-AssessmentADRemoteOSInfo
        )

        $result.Count | Should -Be 2
    }

    It 'supports UseSSL' {

        Mock New-CimSession {
            [PSCustomObject]@{ Id = 'synthetic-session' }
        }

        Mock New-CimSessionOption {
            [PSCustomObject]@{ UseSsl = $true }
        }

        Mock Get-CimInstance {
            [PSCustomObject]@{
                CSName             = 'WEB01'
                Caption            = 'Windows Server'
                Version            = '10.0'
                BuildNumber        = 20348
                OperatingSystemSKU = 20348
                ProductType        = 3
            }
        }

        Mock Remove-CimSession {}

        Get-AssessmentADRemoteOSInfo `
            -ComputerName 'WEB01' `
            -UseSSL |
            Out-Null

        Should -Invoke New-CimSession -Times 1 -Exactly -ParameterFilter {
            $null -ne $SessionOption
        }
    }

    It 'handles a remote query failure' {

        Mock New-CimSession {
            throw 'Synthetic WSMan failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $result = @(
            Get-AssessmentADRemoteOSInfo -ComputerName 'WEB01'
        )

        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotAvailable'
        $result[0].DataAvailability | Should -Be 'NotAvailable'
        $result[0].ErrorType | Should -Be 'RemoteTransportUnavailable'
        $result[0].ErrorMessage | Should -Not -BeNullOrEmpty
        $result[0].IsReadOnly | Should -BeTrue
    }

    It 'has the expected read-only contract' {

        Mock New-CimSession {
            [PSCustomObject]@{ Id = 'synthetic-session' }
        }

        Mock Get-CimInstance {
            [PSCustomObject]@{
                CSName             = 'WEB01'
                Caption            = 'Windows Server'
                Version            = '10.0'
                BuildNumber        = 20348
                OperatingSystemSKU = 20348
                ProductType        = 3
            }
        }

        Mock Remove-CimSession {}

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
