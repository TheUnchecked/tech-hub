#Requires -Version 5.1

Set-StrictMode -Version Latest

Describe 'Get-AssessmentADDNSZoneSecurity' {

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

        function script:New-TestZone {
            param(
                [string]$ZoneName,
                [string]$ZoneType = 'Primary',
                [bool]$IsDsIntegrated = $true,
                [string]$DynamicUpdate = 'Secure'
            )

            [PSCustomObject]@{
                ZoneName       = $ZoneName
                ZoneType       = $ZoneType
                IsDsIntegrated = $IsDsIntegrated
                DynamicUpdate  = $DynamicUpdate
            }
        }

        $script:NewTestDnsProvider = {
            param (
                [object[]]$Zones = @(),
                [string]$ZonesStatus = 'Available',
                [string]$ZonesErrorType,
                [string]$ZonesErrorMessage,
                [hashtable]$TransferSettingsByZone = @{},
                [hashtable]$TransferStatusByZone = @{}
            )

            $Provider = [PSCustomObject]@{
                Server       = $null
                DomainResult = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ DNSRoot = 'example.test' }) }
                ForestResult = [PSCustomObject]@{ Status = 'Available'; Data = @([PSCustomObject]@{ Name = 'example.test' }) }
                ZonesResult  = [PSCustomObject]@{ Status = $ZonesStatus; Data = @($Zones); ErrorType = $ZonesErrorType; ErrorMessage = $ZonesErrorMessage }
                TransferSettingsByZone = $TransferSettingsByZone
                TransferStatusByZone   = $TransferStatusByZone
            }

            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDomainInformation -Value {
                return $this.DomainResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetForestInformation -Value {
                return $this.ForestResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDnsZones -Value {
                return $this.ZonesResult
            }
            Add-Member -InputObject $Provider -MemberType ScriptMethod -Name GetDnsZoneTransferSettings -Value {
                param($ZoneName)

                $Status = 'Available'
                if ($this.TransferStatusByZone.ContainsKey($ZoneName)) {
                    $Status = $this.TransferStatusByZone[$ZoneName]
                }

                $Settings = [PSCustomObject]@{ SecureSecondaries = 'TransferToSecureServers' }
                if ($this.TransferSettingsByZone.ContainsKey($ZoneName)) {
                    $Settings = $this.TransferSettingsByZone[$ZoneName]
                }

                [PSCustomObject]@{
                    Status       = $Status
                    Data         = @($Settings)
                    ErrorType    = $(if ($Status -ne 'Available') { 'AccessDenied' } else { $null })
                    ErrorMessage = $(if ($Status -ne 'Available') { 'Synthetic failure' } else { $null })
                }
            }

            return $Provider
        }
    }

    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'flags NonsecureAndSecure dynamic updates as High' {
        $Zone = New-TestZone -ZoneName 'example.test' -DynamicUpdate 'NonsecureAndSecure'

        $Result = @(
            Get-AssessmentADDNSZoneSecurity -Provider (& $script:NewTestDnsProvider -Zones @($Zone))
        )[0]

        $Result.CheckId | Should -Be 'AD-DNS-ZONE-SECURITY'
        $Result.Category | Should -Be 'DNS'
        $Result.Severity | Should -Be 'High'
    }

    It 'flags TransferAnyServer as Medium when dynamic update is secure' {
        $Zone = New-TestZone -ZoneName 'example.test' -DynamicUpdate 'Secure'

        $Result = @(
            Get-AssessmentADDNSZoneSecurity -Provider (
                & $script:NewTestDnsProvider -Zones @($Zone) -TransferSettingsByZone @{
                    'example.test' = [PSCustomObject]@{ SecureSecondaries = 'TransferAnyServer' }
                }
            )
        )[0]

        $Result.Severity | Should -Be 'Medium'
    }

    It 'reports Informational for a fully hardened zone' {
        $Zone = New-TestZone -ZoneName 'example.test' -DynamicUpdate 'Secure'

        $Result = @(
            Get-AssessmentADDNSZoneSecurity -Provider (& $script:NewTestDnsProvider -Zones @($Zone))
        )[0]

        $Result.Severity | Should -Be 'Informational'
        $Result.Evidence.Weaknesses.Count | Should -Be 0
    }

    It 'skips zones that are not AD-integrated primary zones' {
        $Secondary = New-TestZone -ZoneName 'secondary.test' -ZoneType 'Secondary' -DynamicUpdate 'NonsecureAndSecure'
        $NonDsIntegrated = New-TestZone -ZoneName 'filebased.test' -IsDsIntegrated $false -DynamicUpdate 'NonsecureAndSecure'

        $Results = @(
            Get-AssessmentADDNSZoneSecurity -Provider (& $script:NewTestDnsProvider -Zones @($Secondary, $NonDsIntegrated))
        )

        $Results.Count | Should -Be 0
    }

    It 'returns a single unavailable finding when zones cannot be retrieved' {
        $Result = @(
            Get-AssessmentADDNSZoneSecurity -Provider (
                & $script:NewTestDnsProvider -ZonesStatus 'NotAvailable' -ZonesErrorType 'ModuleUnavailable' -ZonesErrorMessage 'Synthetic: DnsServer module unavailable'
            )
        )[0]

        $Result.Status | Should -Be 'NotAvailable'
        $Result.Evidence.ErrorType | Should -Be 'ModuleUnavailable'
    }

    It 'reports one unavailable finding for a zone whose transfer settings fail, without stopping other zones' {
        $ZoneA = New-TestZone -ZoneName 'a.test' -DynamicUpdate 'Secure'
        $ZoneB = New-TestZone -ZoneName 'b.test' -DynamicUpdate 'Secure'

        $Results = @(
            Get-AssessmentADDNSZoneSecurity -Provider (
                & $script:NewTestDnsProvider -Zones @($ZoneA, $ZoneB) -TransferStatusByZone @{ 'a.test' = 'Error' }
            )
        )

        $Results.Count | Should -Be 2
        ($Results | Where-Object { $_.Title -like '*unavailable for a.test*' }).Count | Should -Be 1
        ($Results | Where-Object { $_.Title -eq 'DNS zone security: b.test' }).Count | Should -Be 1
    }

    It 'creates a provider when invoked without one' {
        $Zone = New-TestZone -ZoneName 'example.test' -DynamicUpdate 'Secure'

        Mock New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -MockWith {
            & $script:NewTestDnsProvider -Zones @($Zone)
        }

        $Results = @(Get-AssessmentADDNSZoneSecurity -Server 'dc01.example.test')

        $Results.Count | Should -Be 1

        Should -Invoke New-AssessmentADProvider -ModuleName TechHub.ActiveDirectory -ParameterFilter {
            $Server -eq 'dc01.example.test'
        } -Times 1
    }

    It 'returns the complete Finding Contract v1 and remains read-only' {
        $Zone = New-TestZone -ZoneName 'example.test' -DynamicUpdate 'Secure'

        $Result = @(
            Get-AssessmentADDNSZoneSecurity -Provider (& $script:NewTestDnsProvider -Zones @($Zone))
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

    It 'contains no direct AD/DNS server cmdlets, modification cmdlets, or dynamic execution' {
        $SourcePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Public\Get-AssessmentADDNSZoneSecurity.ps1'
        $Source = Get-Content -LiteralPath $SourcePath -Raw

        $Source -match '\bGet-AD[A-Za-z]+' | Should -BeFalse
        $Source -match '\bGet-DnsServer[A-Za-z]+' | Should -BeFalse
        $Source -match '\b(Set|New|Remove|Add|Grant)-(AD|DnsServer)[A-Za-z]+' | Should -BeFalse

        $DynamicMarkers = @('Invoke-' + 'Expression', 'Start-' + 'Process', 'Invoke-' + 'Command')

        foreach ($Marker in $DynamicMarkers) {
            $Source -match [regex]::Escape($Marker) | Should -BeFalse
        }
    }
}
