#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADPasswordPolicy' {

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

        $script:NewTestPasswordPolicyProvider = {
            param (
                [object]$DefaultPolicy = [PSCustomObject]@{
                    DistinguishedName           = 'DC=example,DC=test'
                    MinPasswordLength           = 14
                    ComplexityEnabled           = $true
                    ReversibleEncryptionEnabled = $false
                    LockoutThreshold            = 10
                    PasswordHistoryCount        = 24
                    MaxPasswordAge              = (New-TimeSpan -Days 90)
                },
                [string]$DefaultPolicyStatus = 'Available',
                [string]$DefaultPolicyErrorType,
                [string]$DefaultPolicyErrorMessage,
                [object[]]$FineGrainedPolicies = @(),
                [string]$FgppStatus = 'Available'
            )

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
                DefaultPolicyResult = [PSCustomObject]@{
                    Status       = $DefaultPolicyStatus
                    Data         = @($DefaultPolicy)
                    ErrorType    = $DefaultPolicyErrorType
                    ErrorMessage = $DefaultPolicyErrorMessage
                }
                FgppResult = [PSCustomObject]@{
                    Status = $FgppStatus
                    Data   = @($FineGrainedPolicies)
                }
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDefaultDomainPasswordPolicy -Value {
                return $this.DefaultPolicyResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetFineGrainedPasswordPolicies -Value {
                return $this.FgppResult
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'reports Informational for a compliant default policy' {
        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider)
        )[0]

        $Result.CheckId | Should -Be 'AD-PASSWORD-POLICY'
        $Result.Category | Should -Be 'Authentication'
        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.Weaknesses.Count | Should -Be 0
    }

    It 'reports Critical when reversible encryption is enabled' {
        $Policy = [PSCustomObject]@{
            MinPasswordLength           = 14
            ComplexityEnabled           = $true
            ReversibleEncryptionEnabled = $true
            LockoutThreshold            = 10
        }

        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider -DefaultPolicy $Policy)
        )[0]

        $Result.Severity | Should -Be 'Critical'
    }

    It 'reports High when complexity is disabled' {
        $Policy = [PSCustomObject]@{
            MinPasswordLength           = 14
            ComplexityEnabled           = $false
            ReversibleEncryptionEnabled = $false
            LockoutThreshold            = 10
        }

        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider -DefaultPolicy $Policy)
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'reports Medium when account lockout is disabled' {
        $Policy = [PSCustomObject]@{
            MinPasswordLength           = 14
            ComplexityEnabled           = $true
            ReversibleEncryptionEnabled = $false
            LockoutThreshold            = 0
        }

        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider -DefaultPolicy $Policy)
        )[0]

        $Result.Severity | Should -Be 'Medium'
    }

    It 'reports High when minimum password length is below 8' {
        $Policy = [PSCustomObject]@{
            MinPasswordLength           = 7
            ComplexityEnabled           = $true
            ReversibleEncryptionEnabled = $false
            LockoutThreshold            = 10
        }

        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider -DefaultPolicy $Policy)
        )[0]

        $Result.Severity | Should -Be 'High'
    }

    It 'does not include Fine-Grained Password Policies by default' {
        $Results = @(
            Get-AssessmentADPasswordPolicy -Provider (
                & $script:NewTestPasswordPolicyProvider -FineGrainedPolicies @([PSCustomObject]@{ Name = 'Tier0-PSO'; MinPasswordLength = 20 })
            )
        )

        $Results.Count | Should -Be 1
    }

    It 'includes one finding per Fine-Grained Password Policy when requested' {
        $Results = @(
            Get-AssessmentADPasswordPolicy -IncludeFineGrainedPolicies -Provider (
                & $script:NewTestPasswordPolicyProvider -FineGrainedPolicies @(
                    [PSCustomObject]@{ Name = 'Tier0-PSO'; MinPasswordLength = 20; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 5 }
                    [PSCustomObject]@{ Name = 'Weak-PSO'; MinPasswordLength = 6; ComplexityEnabled = $false; ReversibleEncryptionEnabled = $false; LockoutThreshold = 5 }
                )
            )
        )

        $Results.Count | Should -Be 3
        ($Results | Where-Object Title -eq 'Password policy: Tier0-PSO').Severity | Should -Be 'Informational'
        ($Results | Where-Object Title -eq 'Password policy: Weak-PSO').Severity | Should -Be 'High'
    }

    It 'returns structured results for NotAvailable and Error provider status' {
        $Unavailable = @(
            Get-AssessmentADPasswordPolicy -Provider (
                & $script:NewTestPasswordPolicyProvider -DefaultPolicyStatus 'NotAvailable' -DefaultPolicyErrorType 'ModuleUnavailable' -DefaultPolicyErrorMessage 'Synthetic unavailable'
            )
        )[0]

        $Unavailable.Status | Should -Be 'NotAvailable'
        $Unavailable.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'creates a provider when invoked without one' {
        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestPasswordPolicyProvider
        }

        $Results = @(Get-AssessmentADPasswordPolicy -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Result = @(
            Get-AssessmentADPasswordPolicy -Provider (& $script:NewTestPasswordPolicyProvider)
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
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADPasswordPolicy.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-AD[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
