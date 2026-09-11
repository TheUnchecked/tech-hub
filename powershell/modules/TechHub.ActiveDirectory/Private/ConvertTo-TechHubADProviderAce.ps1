#Requires -Version 5.1

Set-StrictMode -Version Latest

function ConvertTo-TechHubADProviderAce {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $IdentityReference = $null
    $ActiveDirectoryRights = $null
    $ObjectTypeGuid = [guid]::Empty
    $AccessControlType = $null
    $IsInherited = $false

    if (
        $null -ne $InputObject.PSObject.Properties['IdentityReference'] -and
        $null -ne $InputObject.PSObject.Properties['IdentityReference'].Value
    ) {
        $IdentityReference = [string]$InputObject.PSObject.Properties['IdentityReference'].Value
    }

    if (
        $null -ne $InputObject.PSObject.Properties['ActiveDirectoryRights'] -and
        $null -ne $InputObject.PSObject.Properties['ActiveDirectoryRights'].Value
    ) {
        $ActiveDirectoryRights = [string]$InputObject.PSObject.Properties['ActiveDirectoryRights'].Value
    }

    if (
        $null -ne $InputObject.PSObject.Properties['ObjectType'] -and
        $null -ne $InputObject.PSObject.Properties['ObjectType'].Value
    ) {
        try {
            $ObjectTypeGuid = [guid]$InputObject.PSObject.Properties['ObjectType'].Value
        }
        catch {
            Write-Verbose -Message 'Provider received an invalid ACE ObjectType.'
        }
    }

    if (
        $null -ne $InputObject.PSObject.Properties['AccessControlType'] -and
        $null -ne $InputObject.PSObject.Properties['AccessControlType'].Value
    ) {
        $AccessControlType = [string]$InputObject.PSObject.Properties['AccessControlType'].Value
    }

    if (
        $null -ne $InputObject.PSObject.Properties['IsInherited'] -and
        $null -ne $InputObject.PSObject.Properties['IsInherited'].Value
    ) {
        try {
            $IsInherited = [bool]$InputObject.PSObject.Properties['IsInherited'].Value
        }
        catch {
            $IsInherited = $false
        }
    }

    [PSCustomObject][ordered]@{
        IdentityReference     = $IdentityReference
        ActiveDirectoryRights = $ActiveDirectoryRights
        ObjectTypeGuid        = $ObjectTypeGuid
        AccessControlType     = $AccessControlType
        IsInherited           = $IsInherited
    }
}
