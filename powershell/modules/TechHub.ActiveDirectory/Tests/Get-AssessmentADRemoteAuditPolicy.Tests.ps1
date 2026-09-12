#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADRemoteAuditPolicy' {

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

        function script:New-AuditRow {
            param(
                [string]$Subcategory,
                [string]$InclusionSetting
            )

            $Row = [PSCustomObject]@{ Subcategory = $Subcategory }
            Add-Member -InputObject $Row -MemberType NoteProperty -Name 'Inclusion Setting' -Value $InclusionSetting
            return $Row
        }

        $script:FullyAuditedRows = @(
            New-AuditRow -Subcategory 'Directory Service Access' -InclusionSetting 'Success and Failure'
            New-AuditRow -Subcategory 'Directory Service Changes' -InclusionSetting 'Success and Failure'
            New-AuditRow -Subcategory 'Kerberos Authentication Service' -InclusionSetting 'Success and Failure'
            New-AuditRow -Subcategory 'Kerberos Service Ticket Operations' -InclusionSetting 'Success'
            New-AuditRow -Subcategory 'Credential Validation' -InclusionSetting 'Success and Failure'
            New-AuditRow -Subcategory 'Logon' -InclusionSetting 'Success and Failure'
            New-AuditRow -Subcategory 'Logoff' -InclusionSetting 'Success'
        )
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'uses the supplied ComputerName list without discovery' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $script:FullyAuditedRows }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-AUDIT-POLICY'
        $Results[0].Category | Should -Be 'AuditingAndLogging'

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -Times 0
    }

    It 'discovers domain controllers by default when ComputerName is not supplied' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $script:FullyAuditedRows }
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith {
            @([PSCustomObject]@{ ComputerName = 'dc01' })
        }

        Get-AssessmentADRemoteAuditPolicy -Server 'dc01.example.test' | Out-Null

        Should -Invoke Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $TargetType -eq 'DomainController'
        } -Times 1
    }

    It 'reports Informational when every evaluated subcategory has some auditing' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $script:FullyAuditedRows }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.NotAuditedSubcategories.Count | Should -Be 0
    }

    It 'reports High when a Directory Service or Kerberos subcategory is not audited' {
        $Rows = @($script:FullyAuditedRows | Where-Object { $_.Subcategory -ne 'Directory Service Access' })
        $Rows += New-AuditRow -Subcategory 'Directory Service Access' -InclusionSetting 'No Auditing'

        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $Rows }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'High'
        $Result.Evidence.NotAuditedSubcategories | Should -Contain 'Directory Service Access'
    }

    It 'reports Medium when a non-high-impact subcategory is not audited' {
        $Rows = @($script:FullyAuditedRows | Where-Object { $_.Subcategory -ne 'Logoff' })
        $Rows += New-AuditRow -Subcategory 'Logoff' -InclusionSetting 'No Auditing'

        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $Rows }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')[0]

        $Result.Severity | Should -Be 'Medium'
    }

    It 'skips subcategories absent from the remote output (for example, on a non-domain-controller)' {
        $Rows = @($script:FullyAuditedRows | Where-Object { $_.Subcategory -notlike 'Directory Service*' })

        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $Rows }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'srv01')[0]

        $Result.Evidence.EvaluatedSubcategories | Should -Not -Contain 'Directory Service Access'
        $Result.Evidence.NotAuditedSubcategories | Should -Not -Contain 'Directory Service Access'
    }

    It 'returns a NotAvailable finding when the remote command fails' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { throw 'Synthetic WinRM failure' }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'unreachable-srv')[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'RemoteQueryError'
    }

    It 'returns a NotAvailable finding when auditpol returns no rows' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'NoData'
    }

    It 'returns nothing when no targets are supplied or discovered' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith { [PSCustomObject]@{} }
        Mock Get-AssessmentADRemoteTargets -ModuleName TechHub.ActiveDirectory -MockWith { @() }

        $Results = @(Get-AssessmentADRemoteAuditPolicy -Server 'dc01.example.test')

        $Results.Count | Should -Be 0
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        Mock Invoke-Command -ModuleName TechHub.ActiveDirectory -MockWith { $script:FullyAuditedRows }

        $Result = @(Get-AssessmentADRemoteAuditPolicy -ComputerName 'dc01')[0]

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

    It 'contains no direct AD cmdlets, modification cmdlets, or Invoke-Expression/Start-Process' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADRemoteAuditPolicy.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
