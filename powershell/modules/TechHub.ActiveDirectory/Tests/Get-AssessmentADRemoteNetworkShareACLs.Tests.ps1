#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteNetworkShareACLs' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-AssessmentADRemoteNetworkShareACLs.ps1"

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

        if (-not (Get-Command Remove-CimSession -ErrorAction SilentlyContinue)) {
            function global:Remove-CimSession {
                param(
                    [Parameter(ValueFromPipeline)]
                    [object]$CimSession
                )
            }
        }
    }

    It 'has the expected read-only contract' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-AssessmentADRemoteNetworkShareACLs.ps1" `
            -Raw

        $content | Should -Match 'ComputerName'
        $content | Should -Match 'ShareName'
        $content | Should -Match 'SharePath'
        $content | Should -Match 'ACL'
        $content | Should -Match 'IsReadOnly'

        $content | Should -Not -Match '\bNew-SmbShare\b'
        $content | Should -Not -Match '\bRemove-SmbShare\b'
        $content | Should -Not -Match '\bGrant-SmbShareAccess\b'
        $content | Should -Not -Match '\bRevoke-SmbShareAccess\b'
    }

    It 'supports pipeline input' {

        Mock New-CimSession {
            throw 'Synthetic CIM failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $errors = @()

        @(
            'WEB01','WEB02' |
            Get-AssessmentADRemoteNetworkShareACLs `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        ) |
            Should -HaveCount 0

        $errors.Count |
            Should -BeGreaterThan 0
    }

    It 'handles remote connection failure' {

        Mock New-CimSession {
            throw 'Synthetic WSMan failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $errors = @()

        $result = @(
            Get-AssessmentADRemoteNetworkShareACLs `
                -ComputerName 'WEB01' `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        )

        $result.Count |
            Should -Be 0

        $errors.Count |
            Should -BeGreaterThan 0
    }

    It 'supports IncludeAdminShares parameter' {

        $command = Get-Command Get-AssessmentADRemoteNetworkShareACLs

        $command.Parameters.ContainsKey('IncludeAdminShares') |
            Should -BeTrue
    }

    It 'supports Credential parameter' {

        $command = Get-Command Get-AssessmentADRemoteNetworkShareACLs

        $command.Parameters.ContainsKey('Credential') |
            Should -BeTrue
    }
}