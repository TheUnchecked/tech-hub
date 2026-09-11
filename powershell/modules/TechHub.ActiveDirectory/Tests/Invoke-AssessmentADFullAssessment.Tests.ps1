#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Invoke-AssessmentADFullAssessment' {

    BeforeAll {

        $script:TestFile = $PSCommandPath
        $script:TestsRoot = Split-Path -Parent $script:TestFile
        $script:ModuleRoot = Split-Path -Parent $script:TestsRoot

        $script:ModulePath = Join-Path `
            -Path $script:ModuleRoot `
            -ChildPath 'TechHub.ActiveDirectory.psm1'

        Import-Module `
            -Name $script:ModulePath `
            -Force `
            -ErrorAction Stop
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $TestDrive -Filter 'AD-Assessment-*.html' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:FakeProvider = [PSCustomObject]@{ Server = $null }
        $Script:FakeAssessment = [PSCustomObject]@{ Findings = @(); Inventory = @() }

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            return $Script:FakeProvider
        }
        Mock Invoke-AssessmentADAssessment -ModuleName TechHub.ActiveDirectory -MockWith {
            return $Script:FakeAssessment
        }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith {
            return @(
                [PSCustomObject]@{ ComputerName = 'SRV01' }
                [PSCustomObject]@{ ComputerName = 'SRV02' }
            )
        }
        Mock Invoke-AssessmentADRemoteAssessment -ModuleName TechHub.ActiveDirectory -MockWith {
            return $Script:FakeAssessment
        }
        Mock Export-AssessmentADAssessmentHtml -ModuleName TechHub.ActiveDirectory -MockWith {}
    }

    It 'runs the AD assessment, discovers targets, and exports one HTML report' {

        $Result = Invoke-AssessmentADFullAssessment -Server 'dc01.example.test' -OutputPath (Join-Path $TestDrive 'report.html')

        Should -Invoke Invoke-AssessmentADAssessment -ModuleName TechHub.ActiveDirectory -Times 1
        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 1
        Should -Invoke Invoke-AssessmentADRemoteAssessment -ModuleName TechHub.ActiveDirectory -Times 2
        Should -Invoke Export-AssessmentADAssessmentHtml -ModuleName TechHub.ActiveDirectory -Times 1

        $Result.ReportPath | Should -Be (Join-Path $TestDrive 'report.html')
        $Result.Assessment | Should -Be $Script:FakeAssessment
    }

    It 'skips remote discovery and collection when -SkipRemoteAssessment is used' {

        Invoke-AssessmentADFullAssessment `
            -Server 'dc01.example.test' `
            -SkipRemoteAssessment `
            -OutputPath (Join-Path $TestDrive 'report.html') |
            Out-Null

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0
        Should -Invoke Invoke-AssessmentADRemoteAssessment -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'bypasses discovery when -ComputerName is supplied' {

        Invoke-AssessmentADFullAssessment `
            -Server 'dc01.example.test' `
            -ComputerName 'SRV03' `
            -OutputPath (Join-Path $TestDrive 'report.html') |
            Out-Null

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0

        Should -Invoke Invoke-AssessmentADRemoteAssessment -ModuleName TechHub.ActiveDirectory -Times 1 -ParameterFilter {
            $ComputerName -eq 'SRV03'
        }
    }

    It 'generates a timestamped default OutputPath when none is supplied' {

        Push-Location $TestDrive
        try {
            $Result = Invoke-AssessmentADFullAssessment -Server 'dc01.example.test' -SkipRemoteAssessment

            $Result.ReportPath | Should -Match 'AD-Assessment-\d{8}-\d{6}\.html$'
        }
        finally {
            Pop-Location
        }
    }

    It 'creates a provider from -Server when none is supplied' {

        Invoke-AssessmentADFullAssessment `
            -Server 'dc01.example.test' `
            -SkipRemoteAssessment `
            -OutputPath (Join-Path $TestDrive 'report.html') |
            Out-Null

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'reuses an explicitly supplied provider without creating another' {

        $SuppliedProvider = [PSCustomObject]@{ Server = 'dc02.example.test' }

        Invoke-AssessmentADFullAssessment `
            -Provider $SuppliedProvider `
            -SkipRemoteAssessment `
            -OutputPath (Join-Path $TestDrive 'report.html') |
            Out-Null

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'contains no direct AD cmdlets, modification cmdlets, or dynamic execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Invoke-AssessmentADFullAssessment.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
