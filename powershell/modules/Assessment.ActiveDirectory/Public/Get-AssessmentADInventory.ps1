#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADInventory {
    <#
    .SYNOPSIS
        Read-only inventory of Active Directory objects.

    .DESCRIPTION
        Collects organizational units, users, computers, managed service
        accounts (MSA/gMSA) and groups directly via the ActiveDirectory
        module. One normalized record per object.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER SearchBase
        Optional Distinguished Name to limit the search.

    .PARAMETER ExpandGroupMembership
        Recursively expands nested group membership. Direct members only
        by default.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ObjectName, OU, ObjectType, Description, Owner, CreationTimestamp,
        UpdateTimestamp, Enabled, LastPasswordChangeTimestamp,
        LastLogonTimestamp, GroupType, GroupScope, GroupMembers
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [switch]$ExpandGroupMembership,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

    $Common = @{}

    if (-not [string]::IsNullOrWhiteSpace($Server)) { $Common.Server = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $Common.Credential = $Credential }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $Common.SearchBase = $SearchBase; $Common.SearchScope = 'Subtree' }

    $IsoFormat = "yyyy-MM-ddTHH:mm:ss'Z'"

    function Convert-ToIso8601 {
        param([Nullable[datetime]]$Date)
        if ($null -eq $Date) { return $null }
        return $Date.ToUniversalTime().ToString($IsoFormat)
    }

    function Convert-FileTimeToIso8601 {
        param([Nullable[int64]]$FileTime)
        if ($null -eq $FileTime -or $FileTime -le 0) { return $null }
        try { [DateTime]::FromFileTimeUtc($FileTime).ToString($IsoFormat) } catch { $null }
    }

    function Get-OwnerSam {
        param([string]$DistinguishedName)
        try {
            $Acl = Get-Acl -Path ("AD:\" + $DistinguishedName) -ErrorAction Stop
            $Owner = $Acl.Owner

            if ([string]::IsNullOrWhiteSpace($Owner)) { return $null }

            if ($Owner -match '^[^\\]+\\(?<sam>.+)$') {
                return $Matches['sam']
            }

            if ($Owner -match '^S-\d-') {
                try {
                    $Sid = New-Object System.Security.Principal.SecurityIdentifier($Owner)
                    $Nt = $Sid.Translate([System.Security.Principal.NTAccount])
                    if ($Nt.Value -match '^[^\\]+\\(?<sam>.+)$') { return $Matches['sam'] }
                }
                catch {}
            }

            return $Owner
        }
        catch {
            return $null
        }
    }

    function New-InventoryRecord {
        param(
            [Microsoft.ActiveDirectory.Management.ADObject]$Object,
            [ValidateSet('User', 'MSA', 'gMSA', 'Group', 'Organizational Unit', 'Computer')]
            [string]$ObjectType,
            [string[]]$GroupMembersSam = @(),
            [bool]$EnabledApplicable = $false,
            [Nullable[bool]]$Enabled = $null,
            [Nullable[int64]]$PwdLastSet = $null,
            [Nullable[int64]]$LastLogonTs = $null,
            [string]$GroupCategory = $null,
            [string]$GroupScope = $null
        )

        $Dn = $Object.DistinguishedName

        if ($Dn -match ',CN=System,') { return }

        $Canonical = $Object.canonicalName
        $OuPath = $null
        $LeafName = $Object.Name

        if ($Canonical) {
            $Parts = $Canonical -split '/'
            if ($Parts.Count -gt 1) {
                $OuPath = ($Parts[0..($Parts.Count - 2)] -join '/')
                $LeafName = $Parts[-1]
            }
            else {
                $OuPath = $Canonical
            }
        }

        $ObjectName = if ($Object.SamAccountName) { $Object.SamAccountName } else { $LeafName }
        $OwnerSam = Get-OwnerSam -DistinguishedName $Dn

        [PSCustomObject][ordered]@{
            ObjectName                  = $ObjectName
            OU                          = $OuPath
            ObjectType                  = $ObjectType
            Description                 = $Object.Description
            Owner                       = $OwnerSam
            CreationTimestamp           = Convert-ToIso8601 $Object.whenCreated
            UpdateTimestamp             = Convert-ToIso8601 $Object.whenChanged
            Enabled                     = if ($EnabledApplicable) { $Enabled } else { $null }
            LastPasswordChangeTimestamp = if ($EnabledApplicable) { Convert-FileTimeToIso8601 $PwdLastSet } else { $null }
            LastLogonTimestamp          = if ($EnabledApplicable) { Convert-FileTimeToIso8601 $LastLogonTs } else { $null }
            GroupType                   = if ($ObjectType -eq 'Group' -and $GroupCategory) { $GroupCategory } else { $null }
            GroupScope                  = if ($ObjectType -eq 'Group' -and $GroupScope) { $GroupScope } else { $null }
            GroupMembers                = if ($ObjectType -eq 'Group' -and $GroupMembersSam.Count -gt 0) { $GroupMembersSam -join ',' } else { $null }
            IsReadOnly                  = $true
        }
    }

    # ----------------------------------------------------------------
    # Organizational Units
    # ----------------------------------------------------------------

    $OuProps = @('distinguishedName', 'name', 'whenCreated', 'whenChanged', 'canonicalName', 'description')
    Get-ADOrganizationalUnit @Common -LDAPFilter '(ou=*)' -Properties $OuProps -ErrorAction SilentlyContinue |
        ForEach-Object { New-InventoryRecord -Object $_ -ObjectType 'Organizational Unit' }

    # ----------------------------------------------------------------
    # Users
    # ----------------------------------------------------------------

    $AccountProps = @('distinguishedName', 'name', 'samAccountName', 'enabled', 'whenCreated', 'whenChanged', 'canonicalName', 'description', 'pwdLastSet', 'lastLogonTimestamp')
    Get-ADUser @Common -Filter * -Properties $AccountProps -ErrorAction SilentlyContinue |
        ForEach-Object {
            New-InventoryRecord -Object $_ -ObjectType 'User' -EnabledApplicable $true `
                -Enabled $_.Enabled -PwdLastSet $_.pwdLastSet -LastLogonTs $_.lastLogonTimestamp
        }

    # ----------------------------------------------------------------
    # Computers
    # ----------------------------------------------------------------

    Get-ADComputer @Common -Filter * -Properties $AccountProps -ErrorAction SilentlyContinue |
        ForEach-Object {
            New-InventoryRecord -Object $_ -ObjectType 'Computer' -EnabledApplicable $true `
                -Enabled $_.Enabled -PwdLastSet $_.pwdLastSet -LastLogonTs $_.lastLogonTimestamp
        }

    # ----------------------------------------------------------------
    # Managed Service Accounts (MSA / gMSA)
    # ----------------------------------------------------------------

    Get-ADObject @Common -LDAPFilter '(objectClass=msDS-ManagedServiceAccount)' -Properties $AccountProps -ErrorAction SilentlyContinue |
        ForEach-Object {
            New-InventoryRecord -Object $_ -ObjectType 'MSA' -EnabledApplicable $true `
                -Enabled $_.Enabled -PwdLastSet $_.pwdLastSet -LastLogonTs $_.lastLogonTimestamp
        }

    Get-ADObject @Common -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties $AccountProps -ErrorAction SilentlyContinue |
        ForEach-Object {
            New-InventoryRecord -Object $_ -ObjectType 'gMSA' -EnabledApplicable $true `
                -Enabled $_.Enabled -PwdLastSet $_.pwdLastSet -LastLogonTs $_.lastLogonTimestamp
        }

    # ----------------------------------------------------------------
    # Groups
    # ----------------------------------------------------------------

    $GroupProps = @('distinguishedName', 'name', 'samAccountName', 'whenCreated', 'whenChanged', 'canonicalName', 'description', 'groupCategory', 'groupScope')

    Get-ADGroup @Common -Filter * -Properties $GroupProps -ErrorAction SilentlyContinue |
        ForEach-Object {
            $Group = $_
            $MembersSam = @()

            try {
                $Members = if ($ExpandGroupMembership) {
                    Get-ADGroupMember @Common -Identity $Group.DistinguishedName -Recursive -ErrorAction Stop
                }
                else {
                    Get-ADGroupMember @Common -Identity $Group.DistinguishedName -ErrorAction Stop
                }

                foreach ($Member in $Members) {
                    try {
                        switch ($Member.objectClass) {
                            'user' {
                                $Resolved = Get-ADUser @Common -Identity $Member.DistinguishedName -Properties SamAccountName -ErrorAction Stop
                                if ($Resolved.SamAccountName) { $MembersSam += $Resolved.SamAccountName }
                            }
                            'computer' {
                                $Resolved = Get-ADComputer @Common -Identity $Member.DistinguishedName -Properties SamAccountName -ErrorAction Stop
                                if ($Resolved.SamAccountName) { $MembersSam += $Resolved.SamAccountName }
                            }
                            'group' {
                                # When -Recursive is used, nested groups are already expanded by
                                # Get-ADGroupMember, so only list the child group's own SAM otherwise.
                                if (-not $ExpandGroupMembership) {
                                    $Resolved = Get-ADGroup @Common -Identity $Member.DistinguishedName -Properties SamAccountName -ErrorAction Stop
                                    if ($Resolved.SamAccountName) { $MembersSam += $Resolved.SamAccountName }
                                }
                            }
                            { $_ -in @('msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount') } {
                                $Resolved = Get-ADObject @Common -Identity $Member.DistinguishedName -Properties SamAccountName -ErrorAction SilentlyContinue
                                if ($Resolved.SamAccountName) { $MembersSam += $Resolved.SamAccountName }
                            }
                            default {
                                # Contacts, foreign security principals, etc. have no SamAccountName.
                            }
                        }
                    }
                    catch {}
                }
            }
            catch {}

            New-InventoryRecord -Object $Group -ObjectType 'Group' -GroupMembersSam $MembersSam `
                -GroupCategory $Group.GroupCategory -GroupScope $Group.GroupScope
        }
}
