#requires -Version 5.1

Set-StrictMode -Version Latest



Describe 'TechHub.ActiveDirectory finding contract v1' {

    BeforeAll {
                $ModuleRoot = (Resolve-Path "$PSScriptRoot/../..").Path
        $ModuleManifest = Join-Path $ModuleRoot 'TechHub.ActiveDirectory.psd1'
        $HelperPath = Join-Path $PSScriptRoot 'TechHubADContractTestHelpers.ps1'

        if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf)) {
            throw "TechHub.ActiveDirectory module manifest not found: $ModuleManifest"
        }

        if (-not (Test-Path -LiteralPath $HelperPath -PathType Leaf)) {
            throw "TechHubADContractTestHelpers.ps1 not found: $HelperPath"
        }

        . $HelperPath
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue

        Import-Module $ModuleManifest -Force -ErrorAction Stop

        if (-not (Get-Command New-TestTechHubADFinding -ErrorAction SilentlyContinue)) {
            throw 'Test helper New-TestTechHubADFinding was not loaded.'
        }
    }

    AfterAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:AssessmentId = [guid]::NewGuid()

        $Script:Domain = [PSCustomObject]@{
            DNSRoot = 'example.test'
        }

        $Script:Forest = [PSCustomObject]@{
            Name = 'example.test'
        }

        $Script:DomainController = [PSCustomObject]@{
            HostName = 'dc01.example.test'
        }
    }

    It 'creates a finding with the required contract properties' {

        $Finding = New-TestTechHubADFinding

        Assert-TechHubADFindingContract `
            -Result $Finding `
            -ExpectedCheckId 'AD-TEST' `
            -ExpectedCheckName 'Synthetic Test Check' `
            -ExpectedCategory 'Delegation'
    }

    It 'preserves assessment identity' {

        $Finding = New-TestTechHubADFinding

        $Finding.AssessmentId |
            Should -Be $Script:AssessmentId
    }

    It 'preserves check identity' {

        $Finding = New-TestTechHubADFinding

        $Finding.CheckId |
            Should -Be 'AD-TEST'

        $Finding.CheckName |
            Should -Be 'Synthetic Test Check'
    }

    It 'generates a valid FindingId' {

        $Finding = New-TestTechHubADFinding

        $Guid = [guid]::Empty

        [guid]::TryParse(
            [string]$Finding.FindingId,
            [ref]$Guid
        ) |
            Should -BeTrue

        $Guid |
            Should -Not -Be ([guid]::Empty)
    }

    It 'preserves security metadata' {

        $Finding = New-TestTechHubADFinding

        $Finding.Severity |
            Should -Be 'High'

        $Finding.Confidence |
            Should -Be 'High'

        $Finding.Status |
            Should -Be 'Open'

        $Finding.IsReadOnly |
            Should -BeTrue
    }

    It 'preserves AD object metadata' {

        $Finding = New-TestTechHubADFinding

        $Finding.ObjectType |
            Should -Be 'user'

        $Finding.DistinguishedName |
            Should -Be 'CN=Test User,CN=Users,DC=example,DC=test'

        $Finding.SamAccountName |
            Should -Be 'test.user'

        $Finding.ObjectGuid |
            Should -Not -BeNullOrEmpty
    }

    It 'preserves evidence risk recommendation and references' {

        $Finding = New-TestTechHubADFinding

        $Finding.Evidence |
            Should -Not -BeNullOrEmpty

        $Finding.Risk |
            Should -Be 'Synthetic risk'

        $Finding.Recommendation |
            Should -Be 'Synthetic recommendation'

        @($Finding.References).Count |
            Should -Be 1

        $Finding.References[0] |
            Should -Be 'https://example.test/reference'
    }

    It 'sets CollectedAt as UTC datetime' {

        $Finding = New-TestTechHubADFinding

        $Finding.CollectedAt |
            Should -BeOfType [datetime]

        $Finding.CollectedAt.Kind |
            Should -Be ([System.DateTimeKind]::Utc)
    }
}