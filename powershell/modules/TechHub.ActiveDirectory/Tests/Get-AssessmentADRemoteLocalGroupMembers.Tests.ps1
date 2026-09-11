#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteLocalGroupMembers' {

    BeforeAll {
        . "$PSScriptRoot\..\Private\Invoke-AssessmentADRemoteCimQuery.ps1"
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteLocalGroupMembers.ps1"

        if (-not (Get-Command New-CimSession -ErrorAction SilentlyContinue)) {
            function global:New-CimSession {
                throw 'Synthetic CIM session'
            }
        }

        if (-not (Get-Command New-CimSessionOption -ErrorAction SilentlyContinue)) {
            function global:New-CimSessionOption {
                throw 'Synthetic CIM option'
            }
        }

        if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
            function global:Get-CimInstance {
                throw 'Synthetic CIM query'
            }
        }

        if (-not (Get-Command Get-CimAssociatedInstance -ErrorAction SilentlyContinue)) {
            function global:Get-CimAssociatedInstance {
                throw 'Synthetic CIM association query'
            }
        }

        if (-not (Get-Command Remove-CimSession -ErrorAction SilentlyContinue)) {
            function global:Remove-CimSession {
                param(
                    [Parameter(ValueFromPipeline)]
                    [object]$CimSession
                )
            }
        }
    }

    It 'returns local groups and members' {

        Mock New-CimSession {
            [PSCustomObject]@{ Id = 'synthetic-session' }
        }

        Mock Get-CimInstance {
            @(
                [PSCustomObject]@{
                    Name = 'Administrators'
                }
            )
        }

        Mock Get-CimAssociatedInstance {
            @(
                [PSCustomObject]@{
                    Domain = 'CONTOSO'
                    Name   = 'Domain Admins'
                }

                [PSCustomObject]@{
                    Domain = 'CONTOSO'
                    Name   = 'svc-admin'
                }
            )
        }

        Mock Remove-CimSession {}

        $result = @(
            Get-AssessmentADRemoteLocalGroupMembers `
                -ComputerName 'WEB01' `
                -ErrorAction SilentlyContinue
        )

        $result.Count |
            Should -Be 1

        $result[0].ComputerName |
            Should -Be 'WEB01'

        $result[0].GroupName |
            Should -Be 'Administrators'

        $result[0].GroupMembers.Count |
            Should -Be 2

        $result[0].GroupMembers.Member |
            Should -Contain 'CONTOSO\Domain Admins'

        $result[0].GroupMembers.Member |
            Should -Contain 'CONTOSO\svc-admin'

        $result[0].Status |
            Should -Be 'Available'
    }

    It 'handles CIM connection failure' {

        Mock New-CimSession {
            throw 'Synthetic WSMan failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $result = @(
            Get-AssessmentADRemoteLocalGroupMembers `
                -ComputerName 'WEB01' `
                -ErrorAction SilentlyContinue
        )

        $result.Count |
            Should -Be 1

        $result[0].Status |
            Should -Be 'NotAvailable'

        $result[0].ErrorType |
            Should -Be 'RemoteTransportUnavailable'

        $result[0].GroupMembers |
            Should -BeNullOrEmpty
    }

    It 'supports pipeline input' {

        Mock New-CimSession {
            throw 'Synthetic CIM failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $result = @(
            'WEB01', 'WEB02' |
            Get-AssessmentADRemoteLocalGroupMembers `
                -ErrorAction SilentlyContinue
        )

        $result.Count |
            Should -Be 2

        $result.Status |
            Should -Contain 'NotAvailable'
    }

    It 'is read-only' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteLocalGroupMembers.ps1" `
            -Raw

        $content | Should -Not -Match '\bRemove-AD'
        $content | Should -Not -Match '\bAdd-AD'
        $content | Should -Not -Match '\bSet-AD'
        $content | Should -Not -Match '\bNew-AD'
        $content | Should -Not -Match '\bDisable-AD'
        $content | Should -Not -Match '\bEnable-AD'
    }

    It 'contains the expected output contract' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteLocalGroupMembers.ps1" `
            -Raw

        $content | Should -Match 'ComputerName'
        $content | Should -Match 'GroupName'
        $content | Should -Match 'GroupMembers'
        $content | Should -Match 'IsReadOnly'
    }
}
