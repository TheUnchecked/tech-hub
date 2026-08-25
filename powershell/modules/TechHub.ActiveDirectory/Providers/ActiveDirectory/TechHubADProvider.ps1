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
    # INTERNAL - MODULE CHECK
    # ========================================================

    hidden [bool] IsActiveDirectoryAvailable() {

        return Test-TechHubADActiveDirectoryAvailability
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
    # INTERNAL - NORMALIZE AD OBJECT
    # ========================================================

    hidden [object] NormalizeADObject(
        [object] $Source
    ) {

        $Result = [ordered]@{}

        $KnownProperties = @(
            'Name'
            'SamAccountName'
            'DistinguishedName'
            'ObjectGUID'
            'ObjectClass'
            'ObjectCategory'
            'UserAccountControl'
            'ServicePrincipalName'
            'MemberOf'
            'msDS-AllowedToDelegateTo'
            'SID'
        )

        foreach ($PropertyName in $KnownProperties) {

            $Property = `
                $Source.PSObject.Properties[$PropertyName]

            if ($null -eq $Property) {

                if ($PropertyName -eq 'msDS-AllowedToDelegateTo') {
                    $Result[$PropertyName] = $null
                }
                else {
                    $Result[$PropertyName] = $null
                }

                continue
            }

            $Value = $Property.Value

            if ($PropertyName -eq 'msDS-AllowedToDelegateTo') {

                if ($null -eq $Value) {

                    $Result[$PropertyName] = $null

                    continue
                }

                $Values = @($Value)

                if ($Values.Count -eq 0) {

                    $Result[$PropertyName] = $null

                    continue
                }

                $StringValues = @(
                    foreach ($Item in $Values) {
                        [string]$Item
                    }
                )

                $Result[$PropertyName] = `
                    [string[]]$StringValues

                continue
            }

            if (
                $PropertyName -eq 'ServicePrincipalName' -or
                $PropertyName -eq 'MemberOf' -or
                $PropertyName -eq 'ObjectClass'
            ) {

                if ($null -eq $Value) {
                    $Result[$PropertyName] = @()
                }
                else {
                    $Result[$PropertyName] = @($Value)
                }

                continue
            }

            $Result[$PropertyName] = $Value
        }

        return [PSCustomObject]$Result
    }

    # ========================================================
    # DOMAIN INFORMATION
    # ========================================================

    [object] GetDomainInformation() {

        $Operation = 'GetDomainInformation'

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Domain = Get-ADDomain @Parameters

            return $this.NewResult(
                $Operation,
                'Available',
                @($Domain),
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
    }

    # ========================================================
    # FOREST INFORMATION
    # ========================================================

    [object] GetForestInformation() {

        $Operation = 'GetForestInformation'

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Forest = Get-ADForest @Parameters

            return $this.NewResult(
                $Operation,
                'Available',
                @($Forest),
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
    }

    # ========================================================
    # DOMAIN CONTROLLERS
    # ========================================================

    [object] GetDomainControllers() {

        $Operation = 'GetDomainControllers'

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                Filter      = '*'
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Controllers = @(
                Get-ADDomainController @Parameters
            )

            return $this.NewResult(
                $Operation,
                'Available',
                $Controllers,
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
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

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                LDAPFilter  = $LDAPFilter
                Properties  = $Properties
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
                $Parameters.SearchBase = $SearchBase
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Objects = @(
                Get-ADObject @Parameters
            )

            $NormalizedObjects = @(
                foreach ($Object in $Objects) {
                    $this.NormalizeADObject($Object)
                }
            )

            return $this.NewResult(
                $Operation,
                'Available',
                $NormalizedObjects,
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
    }

    # ========================================================
    # GROUPS
    # ========================================================

    [object] GetGroups(
        [string] $Filter,
        [string] $SearchBase
    ) {

        $Operation = 'GetGroups'

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($Filter)) {
                $Parameters.Filter = $Filter
            }
            else {
                $Parameters.Filter = '*'
            }

            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
                $Parameters.SearchBase = $SearchBase
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Groups = @(
                Get-ADGroup @Parameters
            )

            return $this.NewResult(
                $Operation,
                'Available',
                $Groups,
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
    }

    # ========================================================
    # GROUP MEMBERS
    # ========================================================

    [object] GetGroupMembers(
        [string] $Identity
    ) {

        $Operation = 'GetGroupMembers'

        if (-not $this.IsActiveDirectoryAvailable()) {
            return $this.NewUnavailableResult($Operation)
        }

        try {

            $Parameters = @{
                Identity    = $Identity
                ErrorAction = 'Stop'
            }

            if (-not [string]::IsNullOrWhiteSpace($this.Server)) {
                $Parameters.Server = $this.Server
            }

            $Members = @(
                Get-ADGroupMember @Parameters
            )

            return $this.NewResult(
                $Operation,
                'Available',
                $Members,
                $null,
                $null
            )
        }
        catch {

            return $this.NewErrorResult(
                $Operation,
                $_.Exception
            )
        }
    }

    # ========================================================
    # PROVIDER STATUS
    # ========================================================

    [object] GetProviderStatus() {

        if ($this.OperationResults.Count -eq 0) {

            if (-not $this.IsActiveDirectoryAvailable()) {

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