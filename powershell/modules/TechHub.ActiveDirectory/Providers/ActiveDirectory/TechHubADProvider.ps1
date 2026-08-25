#requires -Version 5.1

Set-StrictMode -Version Latest

# ============================================================
# TECHHUB - ACTIVE DIRECTORY PROVIDER
# ============================================================
#
# Read-only provider.
#
# Responsibilities:
#   - Active Directory availability
#   - Domain information
#   - Forest information
#   - Domain controllers
#   - AD object retrieval
#   - Group retrieval
#   - Group member retrieval
#   - Operation result normalization
#   - Error classification
#   - Provider status tracking
#
# This file intentionally contains no modifying AD commands.
# ============================================================

class TechHubADProvider {

    [string] $Server

    hidden [System.Collections.Generic.List[object]] $OperationResults

    # ========================================================
    # CONSTRUCTOR
    # ========================================================

    TechHubADProvider() {

        $this.Server = $null

        $this.OperationResults = `
            [System.Collections.Generic.List[object]]::new()
    }

    TechHubADProvider(
        [string] $Server
    ) {

        $this.Server = $Server

        $this.OperationResults = `
            [System.Collections.Generic.List[object]]::new()
    }

    # ========================================================
    # INTERNAL - RESULT CREATION
    # ========================================================

    hidden [object] NewResult(
        [string] $Operation,
        [string] $Status,
        [object] $Data,
        [string] $ErrorType,
        [string] $ErrorMessage
    ) {

        $Result = [PSCustomObject]@{
            Provider    = 'TechHubADProvider'
            Operation   = $Operation
            Status      = $Status
            Data        = @($Data)
            ErrorType   = $ErrorType
            ErrorMessage = $ErrorMessage
            Server      = $this.Server
            IsReadOnly  = $true
        }

        $this.OperationResults.Add($Result)

        return $Result
    }

    # ========================================================
    # INTERNAL - ERROR CLASSIFICATION
    # ========================================================

    hidden [string] GetErrorType(
        [System.Exception] $Exception
    ) {

        if ($null -eq $Exception) {
            return 'Unknown'
        }

        $Message = [string]$Exception.Message

        if ($Message -match '(?i)access\s+denied') {
            return 'AccessDenied'
        }

        if ($Message -match '(?i)\bldap\b') {
            return 'LdapError'
        }

        if ($Message -match '(?i)object\s+not\s+found') {
            return 'ObjectNotFound'
        }

        if (
            $Message -match '(?i)server\s+unavailable' -or
            $Message -match '(?i)domain\s+controller\s+unreachable' -or
            $Message -match '(?i)server\s+unreachable' -or
            $Message -match '(?i)cannot\s+contact' -or
            $Message -match '(?i)network'
        ) {
            return 'ServerUnavailable'
        }

        return 'Unknown'
    }

    # ========================================================
    # INTERNAL - UNAVAILABLE RESULT
    # ========================================================

    hidden [object] NewUnavailableResult(
        [string] $Operation
    ) {

        return $this.NewResult(
            $Operation,
            'NotAvailable',
            @(),
            'ModuleUnavailable',
            'The ActiveDirectory module is not available.'
        )
    }

    # ========================================================
    # INTERNAL - ERROR RESULT
    # ========================================================

    hidden [object] NewErrorResult(
        [string] $Operation,
        [System.Exception] $Exception
    ) {

        $ErrorType = $this.GetErrorType($Exception)

        return $this.NewResult(
            $Operation,
            'Error',
            @(),
            $ErrorType,
            [string]$Exception.Message
        )
    }

    # ========================================================
    # DOMAIN INFORMATION
    # ========================================================

    [object] GetDomainInformation() {

        $Operation = 'GetDomainInformation'

        $ReadResult = Get-TechHubADProviderDomainInformation -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # FOREST INFORMATION
    # ========================================================

    [object] GetForestInformation() {

        $Operation = 'GetForestInformation'

        $ReadResult = Get-TechHubADProviderForestInformation -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # DOMAIN CONTROLLERS
    # ========================================================

    [object] GetDomainControllers() {

        $Operation = 'GetDomainControllers'

        $ReadResult = Get-TechHubADProviderDomainControllers -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # AD OBJECTS
    # ========================================================

    [object] GetADObjects(
        [string] $LDAPFilter,
        [string] $SearchBase,
        [string[]] $Properties
    ) {

        $Operation = 'GetADObjects'

        $ReadResult = Get-TechHubADProviderObjects -LDAPFilter $LDAPFilter -SearchBase $SearchBase -Properties $Properties -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # GROUPS
    # ========================================================

    [object] GetGroups(
        [string] $Filter,
        [string] $SearchBase
    ) {

        $Operation = 'GetGroups'

        $ReadResult = Get-TechHubADProviderGroups -Filter $Filter -SearchBase $SearchBase -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # GROUP MEMBERS
    # ========================================================

    [object] GetGroupMembers(
        [string] $Identity
    ) {

        $Operation = 'GetGroupMembers'

        $ReadResult = Get-TechHubADProviderGroupMembers -Identity $Identity -Server $this.Server
        if (-not $ReadResult.IsAvailable) {
            return $this.NewUnavailableResult($Operation)
        }
        if ($null -ne $ReadResult.Exception) {
            return $this.NewErrorResult($Operation, $ReadResult.Exception)
        }
        return $this.NewResult($Operation, 'Available', $ReadResult.Data, $null, $null)
    }

    # ========================================================
    # PROVIDER STATUS
    # ========================================================

    [object] GetProviderStatus() {

        if ($this.OperationResults.Count -eq 0) {

            if (-not (Test-TechHubADProviderReadAvailability)) {

                return [PSCustomObject]@{
                    Provider     = 'TechHubADProvider'
                    Operation    = 'GetProviderStatus'
                    Status       = 'NotAvailable'
                    Data         = @()
                    ErrorType    = 'ModuleUnavailable'
                    ErrorMessage = 'The ActiveDirectory module is not available.'
                    Server       = $this.Server
                    IsReadOnly   = $true
                }
            }

            return [PSCustomObject]@{
                Provider     = 'TechHubADProvider'
                Operation    = 'GetProviderStatus'
                Status       = 'Available'
                Data         = @()
                ErrorType    = $null
                ErrorMessage = $null
                Server       = $this.Server
                IsReadOnly   = $true
            }
        }

        $Successful = @(
            $this.OperationResults |
                Where-Object {
                    $_.Status -eq 'Available'
                }
        )

        $Failed = @(
            $this.OperationResults |
                Where-Object {
                    $_.Status -eq 'Error'
                }
        )

        $Unavailable = @(
            $this.OperationResults |
                Where-Object {
                    $_.Status -eq 'NotAvailable'
                }
        )

        if (
            $Successful.Count -gt 0 -and
            ($Failed.Count -gt 0 -or $Unavailable.Count -gt 0)
        ) {

            $Status = 'Partial'
        }
        elseif ($Successful.Count -gt 0) {

            $Status = 'Available'
        }
        elseif ($Unavailable.Count -gt 0) {

            $Status = 'NotAvailable'
        }
        elseif ($Failed.Count -gt 0) {

            $Status = 'Error'
        }
        else {

            $Status = 'NotAvailable'
        }

        return [PSCustomObject]@{
            Provider     = 'TechHubADProvider'
            Operation    = 'GetProviderStatus'
            Status       = $Status
            Data         = @($this.OperationResults)
            ErrorType    = $null
            ErrorMessage = $null
            Server       = $this.Server
            IsReadOnly   = $true
        }
    }
}
