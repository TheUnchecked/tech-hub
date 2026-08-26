#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADInventory {
    <#
    .SYNOPSIS
        Collects a read-only Active Directory inventory through the TechHub provider.

    .DESCRIPTION
        Collects users, computers, groups, managed service accounts,
        group managed service accounts and organizational units.

        All directory access is delegated to the provider.
        No Active Directory cmdlets are used directly.

        The function requests only provider-supported LDAP properties.
        Group-specific properties are intentionally not requested globally
        because they are not valid for every object class.

    .PARAMETER Provider
        TechHub Active Directory provider.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER SearchBase
        Optional LDAP search base.

    .OUTPUTS
        Normalized inventory objects.

    .NOTES
        Read-only assessment function.
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Provider,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    # ------------------------------------------------------------
    # Provider initialization
    # ------------------------------------------------------------

    if ($null -eq $Provider) {
        $Provider = New-AssessmentADProvider -Server $Server
    }

    if ($null -eq $Provider) {
        return
    }

    # ------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------

    $queries = @(
        [PSCustomObject]@{
            ObjectType = 'User'
            Filter     = '(&(objectCategory=person)(objectClass=user))'
        }

        [PSCustomObject]@{
            ObjectType = 'Computer'
            Filter     = '(&(objectCategory=computer))'
        }

        [PSCustomObject]@{
            ObjectType = 'MSA'
            Filter     = '(&(objectClass=msDS-ManagedServiceAccount))'
        }

        [PSCustomObject]@{
            ObjectType = 'gMSA'
            Filter     = '(&(objectClass=msDS-GroupManagedServiceAccount))'
        }

        [PSCustomObject]@{
            ObjectType = 'Group'
            Filter     = '(&(objectCategory=group))'
        }

        [PSCustomObject]@{
            ObjectType = 'Organizational Unit'
            Filter     = '(objectCategory=organizationalUnit)'
        }
    )

    # ------------------------------------------------------------
    # Provider-supported common properties
    #
    # IMPORTANT:
    # Do NOT add groupCategory/groupScope here.
    #
    # Those attributes are group-specific and caused:
    #
    #   One or more properties are invalid.
    #   Parameter name: groupCategory
    #
    # ------------------------------------------------------------

    $properties = @(
        'Name'
        'DistinguishedName'
        'ObjectGUID'
        'ObjectClass'
        'SamAccountName'
        'Enabled'
        'Description'
        'canonicalName'
        'whenCreated'
        'whenChanged'
        'pwdLastSet'
        'lastLogonTimestamp'
    )

    # ------------------------------------------------------------
    # Query Active Directory through provider
    # ------------------------------------------------------------

    foreach ($query in $queries) {

        Write-Verbose (
            "Querying AD objects: ObjectType={0}; Filter={1}" -f
            $query.ObjectType,
            $query.Filter
        )

        try {

            $result = $Provider.GetADObjects(
                $query.Filter,
                $SearchBase,
                $properties
            )

        }
        catch {

            Write-Verbose (
                "Provider query failed for ObjectType '{0}': {1}" -f
                $query.ObjectType,
                $_.Exception.Message
            )

            continue
        }

        # --------------------------------------------------------
        # Validate provider result
        # --------------------------------------------------------

        if ($null -eq $result) {
            Write-Verbose (
                "Provider returned NULL for ObjectType '{0}'." -f
                $query.ObjectType
            )

            continue
        }

        if ($result.Status -in @('NotAvailable', 'Error')) {

            Write-Verbose (
                "Provider returned status '{0}' for ObjectType '{1}'. Error: {2}" -f
                $result.Status,
                $query.ObjectType,
                $result.ErrorMessage
            )

            continue
        }

        # --------------------------------------------------------
        # Normalize provider objects
        # --------------------------------------------------------

        foreach ($object in @($result.Data)) {

            if ($null -eq $object) {
                continue
            }

            # ----------------------------------------------------
            # Distinguished Name
            # ----------------------------------------------------

            $dn = $null

            if ($object.PSObject.Properties['DistinguishedName']) {
                $dn = [string]$object.DistinguishedName
            }

            if ([string]::IsNullOrWhiteSpace($dn)) {
                continue
            }

            # ----------------------------------------------------
            # Exclude AD System container and descendants
            # ----------------------------------------------------

            if ($dn -match '(?i)(^|,)CN=System,') {
                continue
            }

            # ----------------------------------------------------
            # Initialize optional properties
            # ----------------------------------------------------

            $name              = $null
            $samAccountName    = $null
            $objectClass       = $null
            $enabled           = $null
            $description       = $null
            $canonicalName     = $null
            $whenCreated       = $null
            $whenChanged       = $null
            $pwdLastSet        = $null
            $lastLogonTimestamp = $null
            $objectGuid        = $null

            # ----------------------------------------------------
            # Safely read provider properties
            # ----------------------------------------------------

            if ($object.PSObject.Properties['Name']) {
                $name = $object.Name
            }

            if ($object.PSObject.Properties['SamAccountName']) {
                $samAccountName = $object.SamAccountName
            }

            if ($object.PSObject.Properties['ObjectClass']) {
                $objectClass = $object.ObjectClass
            }

            if ($object.PSObject.Properties['Enabled']) {
                $enabled = $object.Enabled
            }

            if ($object.PSObject.Properties['Description']) {
                $description = $object.Description
            }

            if ($object.PSObject.Properties['canonicalName']) {
                $canonicalName = $object.canonicalName
            }

            if ($object.PSObject.Properties['whenCreated']) {
                $whenCreated = $object.whenCreated
            }

            if ($object.PSObject.Properties['whenChanged']) {
                $whenChanged = $object.whenChanged
            }

            if ($object.PSObject.Properties['pwdLastSet']) {
                $pwdLastSet = $object.pwdLastSet
            }

            if ($object.PSObject.Properties['lastLogonTimestamp']) {
                $lastLogonTimestamp = $object.lastLogonTimestamp
            }

            # ----------------------------------------------------
            # Object GUID
            # ----------------------------------------------------

            if ($object.PSObject.Properties['ObjectGUID']) {

                try {

                    if ($null -ne $object.ObjectGUID) {
                        $objectGuid = [guid]$object.ObjectGUID
                    }

                }
                catch {

                    $objectGuid = $null
                }
            }

            # ----------------------------------------------------
            # Object name fallback
            # ----------------------------------------------------

            $objectName = $samAccountName

            if ([string]::IsNullOrWhiteSpace([string]$objectName)) {
                $objectName = $name
            }

            # ----------------------------------------------------
            # Normalized assessment object
            # ----------------------------------------------------

            [PSCustomObject][ordered]@{

                ObjectName          = $objectName
                ObjectType          = $query.ObjectType

                Name                = $name
                SamAccountName      = $samAccountName
                DistinguishedName   = $dn
                ObjectGuid          = $objectGuid
                ObjectClass         = $objectClass

                Enabled             = $enabled
                Description         = $description
                CanonicalName       = $canonicalName

                CreationTimestamp   = $whenCreated
                UpdateTimestamp     = $whenChanged

                PasswordLastSet     = $pwdLastSet
                LastLogonTimestamp  = $lastLogonTimestamp

                # Group-specific properties are intentionally left
                # empty here. They must not be requested globally
                # from the provider because the provider validates
                # requested LDAP properties.

                GroupType           = $null
                GroupScope          = $null

                ProviderStatus      = $result.Status
                ProviderServer      = $result.Server
                IsReadOnly          = $true
            }
        }
    }
}