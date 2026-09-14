#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteTargets {
    <#
    .SYNOPSIS
        Discovers and optionally classifies remote Windows computers from Active Directory.

    .DESCRIPTION
        Read-only target discovery for remote assessment, via a direct
        Get-ADComputer query. When TargetType is All, no remote
        connection is required. When TargetType is Server, Client, or
        DomainController, the function classifies each computer using
        Get-AssessmentADRemoteOSInfo (CIM, WSMan falling back to DCOM).

        ProductType classification: 1 = Client, 2 = DomainController, 3 = Server.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER TargetType
        Target selection mode: All, Server, Client, DomainController.

    .PARAMETER SearchBase
        Optional Distinguished Name of an OU/container.

    .PARAMETER IncludeDisabled
        Includes disabled computer accounts. Excluded by default.

    .OUTPUTS
        ComputerName, SamAccountName, DistinguishedName, ObjectGuid,
        Enabled, OperatingSystem, OperatingSystemVersion, ProductType,
        TargetType, CollectionMethod, Status, DataAvailability,
        ErrorType, ErrorMessage, IsReadOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [ValidateSet('All', 'Server', 'Client', 'DomainController')]
        [string]$TargetType = 'All',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    Write-Verbose "Discovering remote assessment targets. TargetType=$TargetType"

    $QueryParameters = @{
        Filter      = '*'
        Properties  = @('Name', 'DistinguishedName', 'ObjectGUID', 'SamAccountName', 'OperatingSystem', 'OperatingSystemVersion', 'Enabled')
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) { $QueryParameters.Server = $Server }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $QueryParameters.SearchBase = $SearchBase }

    try {
        $Computers = @(Get-ADComputer @QueryParameters)
    }
    catch {
        Write-Error -Message "Remote target discovery failed: $($_.Exception.Message)"
        return
    }

    foreach ($Computer in $Computers) {

        if ([string]::IsNullOrWhiteSpace($Computer.Name)) { continue }

        if (-not $IncludeDisabled -and $Computer.Enabled -eq $false) { continue }

        # ------------------------------------------------------------
        # All: no remote connection required.
        # ------------------------------------------------------------

        if ($TargetType -eq 'All') {

            [PSCustomObject][ordered]@{
                ComputerName           = $Computer.Name
                SamAccountName         = $Computer.SamAccountName
                DistinguishedName      = $Computer.DistinguishedName
                ObjectGuid             = $Computer.ObjectGUID
                Enabled                = $Computer.Enabled
                OperatingSystem        = $null
                OperatingSystemVersion = $null
                ProductType            = $null
                TargetType             = 'Unknown'
                CollectionMethod       = 'AD'
                Status                 = 'Available'
                DataAvailability       = 'Available'
                ErrorType              = $null
                ErrorMessage           = $null
                IsReadOnly             = $true
            }

            continue
        }

        # ------------------------------------------------------------
        # Server / Client / DomainController: classify via remote OS query.
        # ------------------------------------------------------------

        Write-Verbose "[$($Computer.Name)] Remote OS classification required."

        try {
            $OSResult = Get-AssessmentADRemoteOSInfo -ComputerName $Computer.Name -ErrorAction Stop

            if ($null -eq $OSResult -or $OSResult.TargetType -ne $TargetType) {
                Write-Verbose "[$($Computer.Name)] Excluded by TargetType='$TargetType'."
                continue
            }

            [PSCustomObject][ordered]@{
                ComputerName           = $Computer.Name
                SamAccountName         = $Computer.SamAccountName
                DistinguishedName      = $Computer.DistinguishedName
                ObjectGuid             = $Computer.ObjectGUID
                Enabled                = $Computer.Enabled
                OperatingSystem        = $OSResult.OSCaption
                OperatingSystemVersion = $OSResult.OSVersion
                ProductType            = $OSResult.ProductType
                TargetType             = $OSResult.TargetType
                CollectionMethod       = $OSResult.CollectionMethod
                Status                 = $OSResult.Status
                DataAvailability       = $OSResult.DataAvailability
                ErrorType              = $OSResult.ErrorType
                ErrorMessage           = $OSResult.ErrorMessage
                IsReadOnly             = $true
            }
        }
        catch {

            Write-Verbose "[$($Computer.Name)] Remote OS classification failed: $($_.Exception.Message)"

            [PSCustomObject][ordered]@{
                ComputerName           = $Computer.Name
                SamAccountName         = $Computer.SamAccountName
                DistinguishedName      = $Computer.DistinguishedName
                ObjectGuid             = $Computer.ObjectGUID
                Enabled                = $Computer.Enabled
                OperatingSystem        = $null
                OperatingSystemVersion = $null
                ProductType            = $null
                TargetType             = 'Unknown'
                CollectionMethod       = 'None'
                Status                 = 'NotAvailable'
                DataAvailability       = 'NotAvailable'
                ErrorType              = 'RemoteOSClassificationError'
                ErrorMessage           = $_.Exception.Message
                IsReadOnly             = $true
            }
        }
    }
}
