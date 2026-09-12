#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteObsoleteOperatingSystem' {

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
    }

    It 'uses the supplied ComputerName list without discovery' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2022 Standard'; OSVersion = '10.0.20348'; OSBuildNumber = '20348'; TargetType = 'Server' }
        }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'srv01')

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-OBSOLETE-OS'
        $Results[0].Category | Should -Be 'Hardening'

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'discovers all targets by default when ComputerName is not supplied' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2022 Standard'; OSVersion = '10.0.20348'; OSBuildNumber = '20348'; TargetType = 'Server' }
        }
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith {
            @([PSCustomObject]@{ ComputerName = 'srv01' })
        }

        Get-AssessmentADRemoteObsoleteOperatingSystem -Server 'dc01.example.test' | Out-Null

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $TargetType -eq 'All'
        } -Times 1
    }

    It 'flags a matching obsolete OS as High' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2008 R2 Standard'; OSVersion = '6.1.7601'; OSBuildNumber = '7601'; TargetType = 'Server' }
        }

        $Result = @(Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'legacy-srv')[0]

        $Result.Severity | Should -Be 'High'
        $Result.Evidence.IsObsolete | Should -BeTrue
        $Result.Evidence.MatchedPattern | Should -Be '*Windows Server 2008*'
    }

    It 'treats a modern OS as Informational' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2022 Standard'; OSVersion = '10.0.20348'; OSBuildNumber = '20348'; TargetType = 'Server' }
        }

        $Result = @(Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'srv01')[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.IsObsolete | Should -BeFalse
    }

    It 'returns a NotAvailable finding when the OS cannot be determined' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'NotAvailable'; ErrorType = 'RemoteTransportUnavailable'; ErrorMessage = 'Synthetic failure' }
        }

        $Result = @(Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'unreachable-srv')[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'RemoteTransportUnavailable'
    }

    It 'returns nothing when no targets are supplied or discovered' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteObsoleteOperatingSystem -Server 'dc01.example.test')

        $Results.Count | Should -Be 0
    }

    It 'supports a custom ObsoleteOSPatterns list' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2022 Standard'; OSVersion = '10.0.20348'; OSBuildNumber = '20348'; TargetType = 'Server' }
        }

        $Result = @(
            Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'srv01' -ObsoleteOSPatterns '*2022*'
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        Mock Get-AssessmentADRemoteOSInfo -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{ Status = 'Available'; OSCaption = 'Microsoft Windows Server 2022 Standard'; OSVersion = '10.0.20348'; OSBuildNumber = '20348'; TargetType = 'Server' }
        }

        $Result = @(Get-AssessmentADRemoteObsoleteOperatingSystem -ComputerName 'srv01')[0]

        @(
            'AssessmentId', 'CheckId', 'CheckName', 'FindingId', 'Title', 'Description',
            'Category', 'Severity', 'Confidence', 'Status', 'AffectedObject', 'ObjectType',
            'DistinguishedName', 'SamAccountName', 'ObjectGuid', 'Evidence', 'Risk',
            'Recommendation', 'References', 'CollectedAt', 'Domain', 'Forest',
            'DomainController', 'IsReadOnly'
        ) | ForEach-Object {
            $Result.PSObject.Properties.Name | Should -Contain $_
        }

        $Result.IsReadOnly | Should -BeTrue
    }

    It 'contains no direct AD cmdlets or modification cmdlets' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADRemoteObsoleteOperatingSystem.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
