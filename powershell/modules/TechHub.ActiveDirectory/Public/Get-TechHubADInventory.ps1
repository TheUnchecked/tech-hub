#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-TechHubADInventory {
    <#
    .SYNOPSIS
        Collects a read-only Active Directory inventory through the TechHub provider.

    .DESCRIPTION
        Collects users, computers, groups, managed service accounts,
        group managed service accounts and organizational units.

        All directory access is delegated to the provider.
        No Active Directory cmdlets are used directly.

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

    if ($null -eq $Provider) {
        $Provider = New-TechHubADProvider -Server $Server
    }

    $queries = @(
        [PSCustomObject]@{
            ObjectType = 'User'
            Filter     = '(&(objectCategory=person)(objectClass=user))'
        },
        [PSCustomObject]@{
            ObjectType = 'Computer'
            Filter     = '(&(objectCategory=computer))'
        },
        [PSCustomObject]@{
            ObjectType = 'MSA'
            Filter     = '(&(objectClass=msDS-ManagedServiceAccount))'
        },
        [PSCustomObject]@{
            ObjectType = 'gMSA'
            Filter     = '(&(objectClass=msDS-GroupManagedServiceAccount))'
        },
        [PSCustomObject]@{
            ObjectType = 'Group'
            Filter     = '(&(objectCategory=group))'
        },
        [PSCustomObject]@{
            ObjectType = 'Organizational Unit'
            Filter     = '(objectCategory=organizationalUnit)'
        }
    )

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
        'groupCategory'
        'groupScope'
    )

    foreach ($query in $queries) {

        $result = $Provider.GetADObjects(
            $query.Filter,
            $SearchBase,
            $properties
        )

        if ($null -eq $result) {
            continue
        }

        if ($result.Status -in @('NotAvailable', 'Error')) {
            continue
        }

        foreach ($object in @($result.Data)) {

            if ($null -eq $object) {
                continue
            }

            # Safely retrieve optional provider properties.
            # This is important because synthetic providers and
            # different provider backends may not expose every LDAP attribute.

            $dn = $null
            if ($object.PSObject.Properties['DistinguishedName']) {
                $dn = [string]$object.DistinguishedName
            }

            if ([string]::IsNullOrWhiteSpace($dn)) {
                continue
            }

            # Exclude the AD System container and descendants.
            if ($dn -match '(?i)(^|,)CN=System,') {
                continue
            }

            $name = $null
            $samAccountName = $null
            $objectClass = $null
            $enabled = $null
            $description = $null
            $canonicalName = $null
            $whenCreated = $null
            $whenChanged = $null
            $pwdLastSet = $null
            $lastLogonTimestamp = $null
            $groupCategory = $null
            $groupScope = $null
            $objectGuid = $null

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

            if ($object.PSObject.Properties['groupCategory']) {
                $groupCategory = $object.groupCategory
            }

            if ($object.PSObject.Properties['groupScope']) {
                $groupScope = $object.groupScope
            }

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

            $objectName = $samAccountName

            if ([string]::IsNullOrWhiteSpace([string]$objectName)) {
                $objectName = $name
            }

            [PSCustomObject][ordered]@{
                ObjectName         = $objectName
                ObjectType         = $query.ObjectType
                Name               = $name
                SamAccountName     = $samAccountName
                DistinguishedName  = $dn
                ObjectGuid         = $objectGuid
                ObjectClass        = $objectClass
                Enabled            = $enabled
                Description        = $description
                CanonicalName      = $canonicalName
                CreationTimestamp  = $whenCreated
                UpdateTimestamp    = $whenChanged
                PasswordLastSet    = $pwdLastSet
                LastLogonTimestamp  = $lastLogonTimestamp
                GroupType          = $groupCategory
                GroupScope         = $groupScope
                ProviderStatus     = $result.Status
                ProviderServer     = $result.Server
                IsReadOnly         = $true
            }
        }
    }
}