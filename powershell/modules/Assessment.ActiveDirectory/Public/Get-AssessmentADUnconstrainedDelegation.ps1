#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADUnconstrainedDelegation {
    <#
    .SYNOPSIS
        Lists AD accounts configured for unconstrained Kerberos delegation.

    .DESCRIPTION
        Read-only query for the TRUSTED_FOR_DELEGATION userAccountControl
        flag (0x80000) on computer and user objects. Reports facts only;
        it does not compute a risk severity.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER SearchBase
        Optional Distinguished Name to limit the search.

    .OUTPUTS
        Name, SamAccountName, DistinguishedName, ObjectGuid, ObjectClass,
        Enabled, ServicePrincipalNames, Domain
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    $LdapFilter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(|(objectCategory=computer)(objectCategory=person)))'

    $QueryParameters = @{
        LDAPFilter  = $LdapFilter
        Properties  = @('DistinguishedName', 'Name', 'ObjectGUID', 'ObjectClass', 'SamAccountName', 'UserAccountControl', 'ServicePrincipalName')
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
        Write-Error -Message "Unconstrained delegation query failed: $($_.Exception.Message)"
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

        [PSCustomObject][ordered]@{
            Name                  = $Object.Name
            SamAccountName        = $Object.SamAccountName
            DistinguishedName     = $Object.DistinguishedName
            ObjectGuid            = $Object.ObjectGUID
            ObjectClass           = $Object.ObjectClass
            Enabled               = $Enabled
            ServicePrincipalNames = @($Object.ServicePrincipalName)
            Domain                = $Domain
            IsReadOnly            = $true
        }
    }
}
