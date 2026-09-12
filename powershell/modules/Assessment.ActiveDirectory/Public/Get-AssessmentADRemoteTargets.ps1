#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteTargets {
    <#
    .SYNOPSIS
        Discovers and optionally classifies remote Windows computers
        from Active Directory.

    .DESCRIPTION
        Read-only target discovery for remote assessment.

        Active Directory is used to discover computer objects.

        When TargetType is All, no remote connection is required.

        When TargetType is Server, Client, or DomainController,
        the function queries the remote operating system using
        Get-AssessmentADRemoteOSInfo.

        Remote OS collection uses:

            WinRM
                |
                +-- fallback --> WMI/DCOM

        ProductType classification:

            1 = Client
            2 = DomainController
            3 = Server

        SearchBase restricts discovery to a specific OU/container.

        Disabled computer accounts are excluded by default.

        The function is read-only.

    .PARAMETER TargetType
        Target selection mode.

        Valid values:

            All
            Server
            Client
            DomainController

    .PARAMETER SearchBase
        Optional Distinguished Name of an OU/container.

    .PARAMETER Provider
        Active Directory assessment provider.

    .PARAMETER IncludeDisabled
        Includes disabled computer accounts.

    .OUTPUTS
        ComputerName
        SamAccountName
        DistinguishedName
        ObjectGuid
        Enabled
        OperatingSystem
        OperatingSystemVersion
        ProductType
        TargetType
        CollectionMethod
        Status
        DataAvailability
        ProviderStatus
        ErrorType
        ErrorMessage
        IsReadOnly
    #>

    [CmdletBinding()]
    param(

        [Parameter()]
        [ValidateSet(
            'All',
            'Server',
            'Client',
            'DomainController'
        )]
        [string]$TargetType = 'All',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Provider,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    begin {

        Write-Verbose `
            "Discovering remote assessment targets. TargetType=$TargetType"

        if (
            -not [string]::IsNullOrWhiteSpace($SearchBase)
        ) {

            Write-Verbose `
                "Using SearchBase: $SearchBase"
        }

        if ($IncludeDisabled) {

            Write-Verbose `
                'Disabled computer accounts will be included.'
        }
        else {

            Write-Verbose `
                'Disabled computer accounts will be excluded.'
        }
    }

    process {

        # ========================================================
        # LDAP FILTER
        # ========================================================

        $LDAPFilter =
            '(&(objectCategory=computer)(objectClass=computer))'

        if (-not $IncludeDisabled) {

            $LDAPFilter =
                '(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        }

        Write-Verbose `
            "LDAP filter: $LDAPFilter"

        # ========================================================
        # AD PROPERTIES
        # ========================================================

        $Properties = @(
            'Name'
            'DistinguishedName'
            'ObjectGUID'
            'ObjectClass'
            'SamAccountName'
            'OperatingSystem'
            'OperatingSystemVersion'
            'UserAccountControl'
        )

        Write-Verbose `
            'Querying Active Directory for computer objects.'

        try {

            # ====================================================
            # ACTIVE DIRECTORY DISCOVERY
            # ====================================================

            $Result = $Provider.GetADObjects(
                $LDAPFilter,
                $SearchBase,
                $Properties
            )

            if ($null -eq $Result) {

                Write-Error `
                    -Message `
                    'Active Directory provider returned no result.'

                return
            }

            if ($Result.Status -ne 'Available') {

                $ProviderError = [string]$Result.ErrorMessage

                if (
                    [string]::IsNullOrWhiteSpace($ProviderError)
                ) {

                    $ProviderError =
                        'Unknown Active Directory provider error.'
                }

                Write-Error `
                    -Message (
                        'Active Directory target discovery failed: {0}' -f
                        $ProviderError
                    )

                return
            }

            # ====================================================
            # PROCESS COMPUTER OBJECTS
            # ====================================================

            foreach ($Computer in @($Result.Data)) {

                if ($null -eq $Computer) {
                    continue
                }

                # ------------------------------------------------
                # Normalize AD properties
                # ------------------------------------------------

                $ComputerName = $null
                $SamAccountName = $null
                $DistinguishedName = $null
                $ObjectGuid = $null
                $Enabled = $null

                if (
                    $Computer.PSObject.Properties['Name']
                ) {

                    $ComputerName =
                        [string]$Computer.Name
                }

                if (
                    $Computer.PSObject.Properties['SamAccountName']
                ) {

                    $SamAccountName =
                        [string]$Computer.SamAccountName
                }

                if (
                    $Computer.PSObject.Properties['DistinguishedName']
                ) {

                    $DistinguishedName =
                        [string]$Computer.DistinguishedName
                }

                if (
                    $Computer.PSObject.Properties['ObjectGUID']
                ) {

                    $ObjectGuid =
                        $Computer.ObjectGUID
                }

                if (
                    $Computer.PSObject.Properties['Enabled']
                ) {

                    $Enabled =
                        [bool]$Computer.Enabled
                }
                elseif (
                    $Computer.PSObject.Properties['UserAccountControl']
                ) {

                    try {

                        $UAC =
                            [int64]$Computer.UserAccountControl

                        $Enabled =
                            (($UAC -band [int64]0x2) -eq 0)
                    }
                    catch {

                        $Enabled = $null
                    }
                }

                if (
                    [string]::IsNullOrWhiteSpace($ComputerName)
                ) {
                    continue
                }

                # =================================================
                # ALL
                #
                # No remote OS query required.
                # =================================================

                if ($TargetType -eq 'All') {

                    [PSCustomObject][ordered]@{

                        ComputerName =
                            $ComputerName

                        SamAccountName =
                            $SamAccountName

                        DistinguishedName =
                            $DistinguishedName

                        ObjectGuid =
                            $ObjectGuid

                        Enabled =
                            $Enabled

                        OperatingSystem =
                            $null

                        OperatingSystemVersion =
                            $null

                        ProductType =
                            $null

                        TargetType =
                            'Unknown'

                        CollectionMethod =
                            'AD'

                        Status =
                            'Available'

                        DataAvailability =
                            'Available'

                        ProviderStatus =
                            'Available'

                        ErrorType =
                            $null

                        ErrorMessage =
                            $null

                        IsReadOnly =
                            $true
                    }

                    continue
                }

                # =================================================
                # REMOTE OS CLASSIFICATION
                # =================================================

                Write-Verbose `
                    "[$ComputerName] Remote OS classification required."

                try {

                    $OSResult =
                        Get-AssessmentADRemoteOSInfo `
                            -ComputerName $ComputerName `
                            -ErrorAction Stop

                    if ($null -eq $OSResult) {

                        Write-Verbose `
                            "[$ComputerName] OS collector returned no result."

                        continue
                    }

                    $RemoteTargetType =
                        [string]$OSResult.TargetType

                    # ---------------------------------------------
                    # Apply requested target type
                    # ---------------------------------------------

                    if (
                        $RemoteTargetType -ne $TargetType
                    ) {

                        Write-Verbose `
                            "[$ComputerName] Classified as '$RemoteTargetType'. Excluded by TargetType='$TargetType'."

                        continue
                    }

                    # ---------------------------------------------
                    # Return classified target
                    # ---------------------------------------------

                    [PSCustomObject][ordered]@{

                        ComputerName =
                            $ComputerName

                        SamAccountName =
                            $SamAccountName

                        DistinguishedName =
                            $DistinguishedName

                        ObjectGuid =
                            $ObjectGuid

                        Enabled =
                            $Enabled

                        OperatingSystem =
                            $OSResult.OSCaption

                        OperatingSystemVersion =
                            $OSResult.OSVersion

                        ProductType =
                            $OSResult.ProductType

                        TargetType =
                            $RemoteTargetType

                        CollectionMethod =
                            $OSResult.CollectionMethod

                        Status =
                            $OSResult.Status

                        DataAvailability =
                            $OSResult.DataAvailability

                        ProviderStatus =
                            'Available'

                        ErrorType =
                            $OSResult.ErrorType

                        ErrorMessage =
                            $OSResult.ErrorMessage

                        IsReadOnly =
                            $true
                    }
                }
                catch {

                    Write-Verbose `
                        "[$ComputerName] Remote OS classification failed: $($_.Exception.Message)"

                    # ---------------------------------------------
                    # A failed remote query must not abort
                    # discovery of the remaining targets.
                    # ---------------------------------------------

                    [PSCustomObject][ordered]@{

                        ComputerName =
                            $ComputerName

                        SamAccountName =
                            $SamAccountName

                        DistinguishedName =
                            $DistinguishedName

                        ObjectGuid =
                            $ObjectGuid

                        Enabled =
                            $Enabled

                        OperatingSystem =
                            $null

                        OperatingSystemVersion =
                            $null

                        ProductType =
                            $null

                        TargetType =
                            'Unknown'

                        CollectionMethod =
                            'None'

                        Status =
                            'NotAvailable'

                        DataAvailability =
                            'NotAvailable'

                        ProviderStatus =
                            'Available'

                        ErrorType =
                            'RemoteOSClassificationError'

                        ErrorMessage =
                            $_.Exception.Message

                        IsReadOnly =
                            $true
                    }
                }
            }
        }
        catch {

            Write-Error `
                -Message (
                    'Remote target discovery failed: {0}' -f
                    $_.Exception.Message
                )
        }
    }
}