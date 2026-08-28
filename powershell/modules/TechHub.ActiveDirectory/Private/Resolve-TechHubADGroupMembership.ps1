#Requires -Version 5.1

Set-StrictMode -Version Latest

function Resolve-TechHubADGroupMembership {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string]$GroupIdentity,

        [Parameter()]
        [string[]]$MembershipPath = @(),

        [Parameter()]
        [hashtable]$VisitedGroups = @{},

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [hashtable]$EmittedRelationships = @{}
    )

    # ============================================================
    # VALIDATE GROUP IDENTITY
    # ============================================================

    if ([string]::IsNullOrWhiteSpace($GroupIdentity)) {

        Write-Verbose `
            -Message 'Skipping empty group identity.'

        return
    }

    # ------------------------------------------------------------
    # Protect against placeholder / invalid identities
    # ------------------------------------------------------------

    if (
        $GroupIdentity -eq 'string' -or
        $GroupIdentity -eq 'System.String'
    ) {

        Write-Verbose `
            -Message (
                'Skipping invalid group identity placeholder: {0}' -f
                $GroupIdentity
            )

        return
    }

    # ============================================================
    # AD PARAMETERS
    # ============================================================

    $ADGroupParameters = @{}

    if (
        -not [string]::IsNullOrWhiteSpace($Server)
    ) {

        $ADGroupParameters.Server = $Server
    }

    # ============================================================
    # RESOLVE GROUP TO REAL AD OBJECT
    # ============================================================

    $ResolvedGroup = $null

    try {

        $ResolvedGroup = Get-ADGroup `
            -Identity $GroupIdentity `
            -Properties `
                DistinguishedName,
                Name,
                SamAccountName,
                ObjectGUID,
                SID `
            @ADGroupParameters `
            -ErrorAction Stop
    }
    catch {

        Write-Verbose `
            -Message (
                'Unable to resolve group {0}: {1}' -f
                $GroupIdentity,
                $_.Exception.Message
            )

        return
    }

    if ($null -eq $ResolvedGroup) {

        Write-Verbose `
            -Message (
                'Group {0} could not be resolved.' -f
                $GroupIdentity
            )

        return
    }

    # ============================================================
    # CANONICAL GROUP DN
    # ============================================================

    $CanonicalGroupIdentity = $null

    if (
        $null -ne
        $ResolvedGroup.PSObject.Properties['DistinguishedName']
    ) {

        $CanonicalGroupIdentity = [string](
            $ResolvedGroup.PSObject.Properties[
                'DistinguishedName'
            ].Value
        )
    }

    if (
        [string]::IsNullOrWhiteSpace(
            $CanonicalGroupIdentity
        )
    ) {

        $CanonicalGroupIdentity = $GroupIdentity
    }

    # ============================================================
    # CIRCULAR MEMBERSHIP PROTECTION
    # ============================================================

    if (
        $VisitedGroups.ContainsKey(
            $CanonicalGroupIdentity
        )
    ) {

        Write-Verbose `
            -Message (
                'Skipping already visited group {0}.' -f
                $CanonicalGroupIdentity
            )

        return
    }

    $VisitedGroups[
        $CanonicalGroupIdentity
    ] = $true

    # ============================================================
    # MEMBERSHIP PATH
    # ============================================================

    $CurrentMembershipPath = @(
        $MembershipPath +
        $CanonicalGroupIdentity
    )

    # ============================================================
    # GET DIRECT MEMBERS
    # ============================================================

    $Members = @()

    try {

        $ADGroupMemberParameters = @{
            Identity   = $CanonicalGroupIdentity
            ErrorAction = 'Stop'
        }

        if (
            -not [string]::IsNullOrWhiteSpace($Server)
        ) {

            $ADGroupMemberParameters.Server = $Server
        }

        $Members = @(
            Get-ADGroupMember `
                @ADGroupMemberParameters
        )
    }
    catch {

        Write-Verbose `
            -Message (
                'Unable to read members of group {0}: {1}' -f
                $CanonicalGroupIdentity,
                $_.Exception.Message
            )

        return
    }

    if ($Members.Count -eq 0) {

        Write-Verbose `
            -Message (
                'Group {0} has no direct members.' -f
                $CanonicalGroupIdentity
            )

        return
    }

    # ============================================================
    # RESOLVE MEMBERS
    # ============================================================

    foreach ($Member in $Members) {

        if ($null -eq $Member) {
            continue
        }

        # --------------------------------------------------------
        # INITIAL VALUES
        # --------------------------------------------------------

        $Resolved = $false

        $Name = $null
        $SamAccountName = $null
        $DistinguishedName = $null
        $ObjectGUID = $null
        $ObjectClass = $null
        $SID = $null

        $Enabled = $null
        $AdminCount = $null
        $PasswordNeverExpires = $null

        $MembershipType = 'Direct'

        if ($MembershipPath.Count -gt 0) {
            $MembershipType = 'Indirect'
        }

        $EmitDirectMember = $true

        # --------------------------------------------------------
        # READ BASE PROPERTIES
        # --------------------------------------------------------

        if (
            $null -ne
            $Member.PSObject.Properties['Name']
        ) {

            $Name = [string]$Member.Name
        }

        if (
            $null -ne
            $Member.PSObject.Properties['SamAccountName']
        ) {

            $SamAccountName = `
                [string]$Member.SamAccountName
        }

        if (
            $null -ne
            $Member.PSObject.Properties['DistinguishedName']
        ) {

            $DistinguishedName = `
                [string]$Member.DistinguishedName
        }

        if (
            $null -ne
            $Member.PSObject.Properties['ObjectGUID']
        ) {

            try {

                $ObjectGUID = [guid]$Member.ObjectGUID
            }
            catch {

                $ObjectGUID = $null
            }
        }

        if (
            $null -ne
            $Member.PSObject.Properties['objectClass']
        ) {

            $MemberObjectClasses = @(
                $Member.PSObject.Properties['objectClass'].Value
            ) | ForEach-Object {
                [string]$_
            }

            if ($MemberObjectClasses -contains 'user') {
                $ObjectClass = 'User'
            }
            elseif ($MemberObjectClasses -contains 'computer') {
                $ObjectClass = 'Computer'
            }
            elseif ($MemberObjectClasses -contains 'group') {
                $ObjectClass = 'Group'
            }
        }

        if (
            $null -ne
            $Member.PSObject.Properties['SID']
        ) {

            $SID = [string]$Member.SID
        }

        # ========================================================
        # RESOLVE USER / COMPUTER / GROUP
        # ========================================================

        if (
            [string]::IsNullOrWhiteSpace(
                $DistinguishedName
            )
        ) {

            Write-Verbose `
                -Message (
                    'Member {0} has no DistinguishedName.' -f
                    $Name
                )

            continue
        }

        $RelationshipKey = @(
            $CurrentMembershipPath
            $DistinguishedName
        ) -join '|'

        if ($EmittedRelationships.ContainsKey($RelationshipKey)) {
            continue
        }

        $EmittedRelationships[$RelationshipKey] = $true

        try {

            switch ($ObjectClass) {

                'Group' {

                    $DetailParameters = @{
                        Identity    = $DistinguishedName
                        Properties  = @(
                            'adminCount',
                            'SID',
                            'ObjectGUID'
                        )
                        ErrorAction = 'Stop'
                    }

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $Server
                        )
                    ) {

                        $DetailParameters.Server = $Server
                    }

                    $Detail = Get-ADGroup `
                        @DetailParameters

                    $Resolved = $true

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['Name']
                    ) {
                        $Name = [string]$Detail.Name
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['SamAccountName']
                    ) {
                        $SamAccountName = `
                            [string]$Detail.SamAccountName
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['DistinguishedName']
                    ) {
                        $DistinguishedName = `
                            [string]$Detail.DistinguishedName
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['ObjectGUID']
                    ) {
                        try {
                            $ObjectGUID = [guid]$Detail.ObjectGUID
                        }
                        catch {
                            $ObjectGUID = $null
                        }
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['SID']
                    ) {
                        $SID = [string]$Detail.SID
                    }

                    $ChildMembers = @(
                        Resolve-TechHubADGroupMembership `
                            -GroupIdentity $DistinguishedName `
                            -MembershipPath $CurrentMembershipPath `
                            -VisitedGroups $VisitedGroups `
                            -Server $Server `
                            -EmittedRelationships $EmittedRelationships
                    )

                    [PSCustomObject][ordered]@{
                        Name                  = $Name
                        SamAccountName        = $SamAccountName
                        DistinguishedName     = $DistinguishedName
                        ObjectGUID            = $ObjectGUID
                        ObjectClass           = 'Group'
                        SID                   = $SID
                        Enabled               = $null
                        AdminCount            = $null
                        PasswordNeverExpires  = $null
                        MembershipType        = 'Indirect'
                        MembershipPath       = $CurrentMembershipPath
                        Resolved              = $Resolved
                    }

                    foreach ($ChildMember in $ChildMembers) {
                        $ChildMember
                    }

                    $EmitDirectMember = $false
                }

                'User' {

                    $DetailParameters = @{
                        Identity    = $DistinguishedName
                        Properties  = @(
                            'Enabled',
                            'adminCount',
                            'PasswordNeverExpires',
                            'SID',
                            'ObjectGUID'
                        )
                        ErrorAction = 'Stop'
                    }

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $Server
                        )
                    ) {

                        $DetailParameters.Server = $Server
                    }

                    $Detail = Get-ADUser `
                        @DetailParameters

                    $Resolved = $true

                    $Name = [string]$Detail.Name
                    $SamAccountName = `
                        [string]$Detail.SamAccountName
                    $DistinguishedName = `
                        [string]$Detail.DistinguishedName

                    try {
                        $ObjectGUID = [guid]$Detail.ObjectGUID
                    }
                    catch {
                        $ObjectGUID = $null
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['SID']
                    ) {
                        $SID = [string]$Detail.SID
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['Enabled']
                    ) {
                        $Enabled = [bool]$Detail.Enabled
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['adminCount']
                    ) {
                        $AdminCount = $Detail.adminCount
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties[
                            'PasswordNeverExpires'
                        ]
                    ) {
                        $PasswordNeverExpires = `
                            [bool]$Detail.PasswordNeverExpires
                    }
                }

                'Computer' {

                    $DetailParameters = @{
                        Identity    = $DistinguishedName
                        Properties  = @(
                            'Enabled',
                            'adminCount',
                            'PasswordNeverExpires',
                            'SID',
                            'ObjectGUID'
                        )
                        ErrorAction = 'Stop'
                    }

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $Server
                        )
                    ) {

                        $DetailParameters.Server = $Server
                    }

                    $Detail = Get-ADComputer `
                        @DetailParameters

                    $Resolved = $true

                    $Name = [string]$Detail.Name
                    $SamAccountName = `
                        [string]$Detail.SamAccountName
                    $DistinguishedName = `
                        [string]$Detail.DistinguishedName

                    try {
                        $ObjectGUID = [guid]$Detail.ObjectGUID
                    }
                    catch {
                        $ObjectGUID = $null
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['SID']
                    ) {
                        $SID = [string]$Detail.SID
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['Enabled']
                    ) {
                        $Enabled = [bool]$Detail.Enabled
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties['adminCount']
                    ) {
                        $AdminCount = $Detail.adminCount
                    }

                    if (
                        $null -ne
                        $Detail.PSObject.Properties[
                            'PasswordNeverExpires'
                        ]
                    ) {
                        $PasswordNeverExpires = `
                            [bool]$Detail.PasswordNeverExpires
                    }
                }

                default {

                    Write-Verbose `
                        -Message (
                            'Unsupported member object class {0} for {1}.' -f
                            $ObjectClass,
                            $DistinguishedName
                        )
                }
            }
        }
        catch {

            Write-Verbose `
                -Message (
                    'Unable to resolve member {0}: {1}' -f
                    $DistinguishedName,
                    $_.Exception.Message
                )
        }

        # ========================================================
        # RETURN MEMBER
        # ========================================================

        if ($EmitDirectMember) {
            [PSCustomObject][ordered]@{

                Name                 = $Name

                SamAccountName       = $SamAccountName

                DistinguishedName    = $DistinguishedName

                ObjectGUID           = $ObjectGUID

                ObjectClass          = $ObjectClass

                SID                  = $SID

                Enabled              = $Enabled

                AdminCount           = $AdminCount

                PasswordNeverExpires = `
                    $PasswordNeverExpires

                MembershipType       = $MembershipType

                MembershipPath       = `
                    $CurrentMembershipPath

                Resolved             = $Resolved
            }
        }
    }
}