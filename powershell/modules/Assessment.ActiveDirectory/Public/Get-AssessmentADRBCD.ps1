#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRBCD {
    <#
    .SYNOPSIS
        Lists AD objects configured for resource-based constrained delegation (RBCD).

    .DESCRIPTION
        Read-only query for msDS-AllowedToActOnBehalfOfOtherIdentity on
        computer, user and group objects. The security descriptor is
        parsed into the list of identities allowed to delegate to the
        object. Reports facts only; it does not compute a risk severity.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER SearchBase
        Optional Distinguished Name to limit the search.

    .OUTPUTS
        Name, SamAccountName, DistinguishedName, ObjectGuid, ObjectClass,
        Enabled, AllowedIdentities (SID/IdentityReference/AccessType),
        Domain
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    $LdapFilter = '(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(|(objectCategory=computer)(objectCategory=person)(objectCategory=group)))'

    $QueryParameters = @{
        LDAPFilter  = $LdapFilter
        Properties  = @('DistinguishedName', 'Name', 'ObjectGUID', 'ObjectClass', 'SamAccountName', 'UserAccountControl', 'msDS-AllowedToActOnBehalfOfOtherIdentity')
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $QueryParameters.Server = $Server
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $QueryParameters.SearchBase = $SearchBase
    }

    $Domain = $null

    try {
        $DomainContextParameters = @{ ErrorAction = 'Stop' }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $DomainContextParameters.Server = $Server
        }

        $Domain = (Get-ADDomain @DomainContextParameters).DNSRoot
    }
    catch {
        Write-Verbose -Message "Unable to resolve domain context: $($_.Exception.Message)"
    }

    try {
        $Objects = @(Get-ADObject @QueryParameters)
    }
    catch {
        Write-Error -Message "RBCD query failed: $($_.Exception.Message)"
        return
    }

    foreach ($Object in $Objects) {

        $Enabled = $null

        try {
            $Enabled = (([int64]$Object.UserAccountControl -band 0x2) -eq 0)
        }
        catch {
            $Enabled = $null
        }

        $AllowedIdentities = @()

        $Descriptor = $Object.'msDS-AllowedToActOnBehalfOfOtherIdentity'

        if ($null -ne $Descriptor) {
            try {
                $AllowedIdentities = @(ConvertFrom-AssessmentADRBCDDescriptor -Descriptor $Descriptor)
            }
            catch {
                Write-Verbose -Message "Unable to parse RBCD descriptor on $($Object.DistinguishedName): $($_.Exception.Message)"
            }
        }

        [PSCustomObject][ordered]@{
            Name              = $Object.Name
            SamAccountName    = $Object.SamAccountName
            DistinguishedName = $Object.DistinguishedName
            ObjectGuid        = $Object.ObjectGUID
            ObjectClass       = $Object.ObjectClass
            Enabled           = $Enabled
            AllowedIdentities = $AllowedIdentities
            Domain            = $Domain
            IsReadOnly        = $true
        }
    }
}
