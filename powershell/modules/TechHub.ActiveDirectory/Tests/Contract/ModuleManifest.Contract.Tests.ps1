#requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'TechHub.ActiveDirectory module manifest contract' {

    BeforeAll {

        $ModuleRoot = (Resolve-Path "$PSScriptRoot/../..").Path
        $ModuleManifest = Join-Path $ModuleRoot 'TechHub.ActiveDirectory.psd1'

        if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf)) {
            throw "TechHub.ActiveDirectory module manifest not found: $ModuleManifest"
        }

        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue

        Import-Module $ModuleManifest -Force -ErrorAction Stop

        $Script:DeclaredExports = @(
            (Import-PowerShellDataFile -Path $ModuleManifest).FunctionsToExport
        )
    }

    AfterAll {
        Remove-Module TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'declares at least one exported function' {

        $Script:DeclaredExports.Count |
            Should -BeGreaterThan 0
    }

    It 'does not declare duplicate function names' {

        $Duplicates = @(
            $Script:DeclaredExports |
                Group-Object |
                Where-Object { $_.Count -gt 1 }
        )

        $Duplicates.Count |
            Should -Be 0
    }

    It 'every declared FunctionsToExport entry resolves to a real, loaded command' {

        $Module = Get-Module TechHub.ActiveDirectory

        $Module |
            Should -Not -BeNullOrEmpty

        $MissingFunctions = @(
            $Script:DeclaredExports |
                Where-Object {
                    -not (
                        Get-Command `
                            -Name $_ `
                            -Module $Module.Name `
                            -ErrorAction SilentlyContinue
                    )
                }
        )

        $MissingFunctions |
            Should -Be @()
    }
}
