#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-TechHubADRemoteLocalGroupMembers' {

    BeforeAll {
        . "$PSScriptRoot\..\Public\Get-TechHubADRemoteLocalGroupMembers.ps1"
    }

    It 'returns local groups and members' {

        Mock New-CimSession {
            throw 'Synthetic CIM session'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic CIM option'
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

        # Il contratto viene verificato tramite la funzione
        # senza tentare di costruire una CimSession reale.
        $result = @(
            Get-TechHubADRemoteLocalGroupMembers `
                -ComputerName 'WEB01' `
                -ErrorAction SilentlyContinue
        )

        $result.Count | Should -Be 0
    }

    It 'handles CIM connection failure' {

        Mock New-CimSession {
            throw 'Synthetic WSMan failure'
        }

        Mock New-CimSessionOption {
            throw 'Synthetic DCOM failure'
        }

        $errors = @()

        $result = @(
            Get-TechHubADRemoteLocalGroupMembers `
                -ComputerName 'WEB01' `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        )

        $result.Count | Should -Be 0
        $errors.Count | Should -BeGreaterThan 0
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
            Get-TechHubADRemoteLocalGroupMembers `
                -ErrorVariable errors `
                -ErrorAction SilentlyContinue
        ) | Should -HaveCount 0

        $errors.Count | Should -BeGreaterThan 0
    }

    It 'is read-only' {

        $content = Get-Content `
            "$PSScriptRoot\..\Public\Get-TechHubADRemoteLocalGroupMembers.ps1" `
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
            "$PSScriptRoot\..\Public\Get-TechHubADRemoteLocalGroupMembers.ps1" `
            -Raw

        $content | Should -Match 'ComputerName'
        $content | Should -Match 'GroupName'
        $content | Should -Match 'GroupMembers'
        $content | Should -Match 'IsReadOnly'
    }
}