#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteCredentialGuardStatus' {

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
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1) }
            }
        }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'dc01')

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-CREDENTIAL-GUARD'
        $Results[0].Category | Should -Be 'Hardening'

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'discovers domain controllers by default when ComputerName is not supplied' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1) }
            }
        }
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith {
            @([PSCustomObject]@{ ComputerName = 'dc01' })
        }

        Get-AssessmentADRemoteCredentialGuardStatus -Server 'dc01.example.test' | Out-Null

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $TargetType -eq 'DomainController'
        } -Times 1
    }

    It 'reports Informational when Credential Guard is running' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1) }
            }
        }

        $Result = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.CredentialGuardRunning | Should -BeTrue
    }

    It 'reports Medium when virtualization-based security is not running' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 0; SecurityServicesRunning = @() }
            }
        }

        $Result = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Medium'
    }

    It 'reports Medium when VBS is running but Credential Guard specifically is not' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(2) }
            }
        }

        $Result = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Medium'
        $Result.Evidence.CredentialGuardRunning | Should -BeFalse
    }

    It 'returns a NotAvailable finding when the class cannot be read' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status       = 'Error'
                ErrorType    = 'RemoteQueryError'
                ErrorMessage = 'Synthetic: class not found'
            }
        }

        $Result = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'legacy-srv')[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'RemoteQueryError'
    }

    It 'returns nothing when no targets are supplied or discovered' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteCredentialGuardStatus -Server 'dc01.example.test')

        $Results.Count | Should -Be 0
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        Mock Invoke-AssessmentADRemoteCimQuery -ModuleName TechHub.ActiveDirectory -MockWith {
            [PSCustomObject]@{
                Status = 'Available'
                Data   = [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1) }
            }
        }

        $Result = @(Get-AssessmentADRemoteCredentialGuardStatus -ComputerName 'dc01')[0]

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

    It 'contains no direct AD cmdlets, modification cmdlets, or WinRM execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADRemoteCredentialGuardStatus.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
