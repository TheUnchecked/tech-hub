#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADASREPRoasting' {

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

        $script:NewTestASREPProviderResult = {
            param (
                [string]$Status = 'Available',
                [object[]]$Data = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            [PSCustomObject][ordered]@{
                Provider     = 'TechHubADProvider'
                Operation    = 'GetADObjects'
                Status       = $Status
                Data         = @($Data)
                ErrorType    = $ErrorType
                ErrorMessage = $ErrorMessage
                Server       = $null
                IsReadOnly   = $true
            }
        }

        $script:NewTestASREPProvider = {
            param (
                [string]$ObjectStatus = 'Available',
                [object[]]$Objects = @(),
                [string]$ErrorType,
                [string]$ErrorMessage
            )

            $ObjectResult = & $script:NewTestASREPProviderResult `
                -Status $ObjectStatus `
                -Data $Objects `
                -ErrorType $ErrorType `
                -ErrorMessage $ErrorMessage

            $Provider = [PSCustomObject]@{
                Server       = $null
                DomainResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ DNSRoot = 'example.test' })
                }
                ForestResult = [PSCustomObject]@{
                    Status = 'Available'
                    Data   = @([PSCustomObject]@{ Name = 'example.test' })
                }
                ObjectResult = $ObjectResult
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetADObjects -Value {
                param($LdapFilter, $SearchBase, $Properties)
                return $this.ObjectResult
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Script:Regular = [PSCustomObject]@{
            Name               = 'jdoe'
            DistinguishedName  = 'CN=jdoe,DC=example,DC=test'
            ObjectGUID         = [guid]'33333333-3333-3333-3333-333333333333'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'jdoe'
            UserAccountControl = 4194304
            Enabled            = $true
            AdminCount         = 0
        }

        $Script:Privileged = [PSCustomObject]@{
            Name               = 'break-glass-admin'
            DistinguishedName  = 'CN=break-glass-admin,DC=example,DC=test'
            ObjectGUID         = [guid]'44444444-4444-4444-4444-444444444444'
            ObjectClass        = @('top', 'person', 'user')
            SamAccountName     = 'break-glass-admin'
            UserAccountControl = 4194306
            Enabled            = $false
            AdminCount         = 1
        }
    }

    It 'detects accounts with DONT_REQUIRE_PREAUTH from synthetic provider data' {
        $Results = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($Script:Regular)
            )
        )

        $Results.Count | Should -Be 1
        $Results[0].CheckId | Should -Be 'AD-ASREP-ROASTING'
        $Results[0].Category | Should -Be 'Kerberos'
        $Results[0].Evidence.DontRequirePreauth | Should -BeTrue
    }

    It 'skips accounts that require preauthentication' {
        $NoFlag = $Script:Regular.PSObject.Copy()
        $NoFlag.UserAccountControl = 512

        $Results = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($NoFlag)
            )
        )

        $Results.Count | Should -Be 0
    }

    It 'treats an enabled non-privileged account as High' {
        $Result = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($Script:Regular)
            )
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'escalates a privileged account to Critical when enabled' {
        $EnabledPrivileged = $Script:Privileged.PSObject.Copy()
        $EnabledPrivileged.Enabled = $true
        $EnabledPrivileged.UserAccountControl = 4194304

        $Result = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($EnabledPrivileged)
            )
        )[0]

        $Result.Severity | Should -Be 'Critical'
    }

    It 'lowers severity to Informational for disabled accounts' {
        $Result = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($Script:Privileged)
            )
        )[0]

        $Result.Severity | Should -Be 'Informational'
    }

    It 'excludes accounts matching ExcludedAccountPatterns' {
        $Results = @(
            Get-AssessmentADASREPRoasting `
                -Provider (& $script:NewTestASREPProvider -Objects @($Script:Regular)) `
                -ExcludedAccountPatterns 'jdoe'
        )

        $Results.Count | Should -Be 0
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Unavailable = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -ObjectStatus 'NotAvailable' -ErrorType 'ModuleUnavailable' -ErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Unavailable.Status | Should -Be 'NotAvailable'
        $Unavailable.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestASREPProvider -Objects @($Script:Regular)
        }

        $Results = @(Get-AssessmentADASREPRoasting -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Result = @(
            Get-AssessmentADASREPRoasting -Provider (
                & $script:NewTestASREPProvider -Objects @($Script:Regular)
            )
        )[0]

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

    It 'contains no direct AD cmdlets, modification cmdlets, or dynamic execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADASREPRoasting.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Script' + 'Block', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
