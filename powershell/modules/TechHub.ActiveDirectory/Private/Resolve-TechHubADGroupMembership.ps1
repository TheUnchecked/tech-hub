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
        [hashtable]$VisitedGroups = @{}
    )

    # ============================================================
    # CYCLE PROTECTION
    # ============================================================

    if (
        $VisitedGroups.ContainsKey(
            $GroupIdentity
        )
    ) {

        Write-Verbose -Message (
            'Skipping already visited group {0}.' -f
            $GroupIdentity
        )

        return
    }

    $VisitedGroups[$GroupIdentity] = $true

    # ============================================================
    # COLLECT DIRECT MEMBERS
    # ============================================================

    $Members = @()

    try {

        $Members = @(
            Get-ADGroupMember `
                -Identity $GroupIdentity `
                -ErrorAction Stop
        )
    }
    catch {

        Write-Verbose -Message (
            'Unable to read members of group {0}: {1}' -f
            $GroupIdentity,
            $_.Exception.Message
        )

        return
    }

    # ============================================================
    # NORMALIZE MEMBERS
    # ============================================================

    foreach ($Member in $Members) {

        $Name                 = $null
        $SamAccountName       = $null
        $ObjectClass          = 'Unknown'
        $ObjectGuid           = $null
        $DistinguishedName    = $null
        $Enabled              = $null
        $AdminCount           = $null
        $PasswordNeverExpires = $null
        $MemberSid            = $null
        $UserAccountControl   = $null
        $Detail               = $null

        # ========================================================
        # READ BASE PROPERTIES FROM Get-ADGroupMember
        # ========================================================

        foreach (
            $PropertyName in @(
                'Name'
                'SamAccountName'
                'DistinguishedName'
                'ObjectClass'
                'ObjectGUID'
                'SID'
            )
        ) {

            if (
                $null -ne
                $Member.PSObject.Properties[
                    $PropertyName
                ]
            ) {

                $Value =
                    $Member.PSObject.Properties[
                        $PropertyName
                    ].Value

                switch ($PropertyName) {

                    'Name' {

                        $Name =
                            [string]$Value
                    }

                    'SamAccountName' {

                        $SamAccountName =
                            [string]$Value
                    }

                    'DistinguishedName' {

                        $DistinguishedName =
                            [string]$Value
                    }

                    'ObjectClass' {

                        $MemberClasses =
                            @($Value)

                        if (
                            $MemberClasses -contains 'user'
                        ) {

                            $ObjectClass =
                                'User'
                        }
                        elseif (
                            $MemberClasses -contains 'computer'
                        ) {

                            $ObjectClass =
                                'Computer'
                        }
                        elseif (
                            $MemberClasses -contains 'group'
                        ) {

                            $ObjectClass =
                                'Group'
                        }
                    }

                    'ObjectGUID' {

                        try {

                            $ObjectGuid =
                                [guid]$Value
                        }
                        catch {

                            Write-Verbose -Message `
                                'A member has an invalid ObjectGUID.'
                        }
                    }

                    'SID' {

                        $MemberSid =
                            [string]$Value
                    }
                }
            }
        }

        # ========================================================
        # RESOLVE OBJECT DETAILS
        #
        # IMPORTANT:
        #
        # PasswordNeverExpires is retrieved from Get-ADUser.
        # It is NOT requested from Get-ADObject.
        # ========================================================

        if (
            -not [string]::IsNullOrWhiteSpace(
                $DistinguishedName
            )
        ) {

            try {

                switch ($ObjectClass) {

                    # =================================================
                    # USER
                    # =================================================

                    'User' {

                        $Detail =
                            Get-ADUser `
                                -Identity $DistinguishedName `
                                -Properties `
                                    Enabled,
                                    adminCount,
                                    PasswordNeverExpires,
                                    UserAccountControl,
                                    SID,
                                    ObjectGUID,
                                    DistinguishedName,
                                    SamAccountName,
                                    Name `
                                -ErrorAction Stop
                    }

                    # =================================================
                    # COMPUTER
                    # =================================================

                    'Computer' {

                        $Detail =
                            Get-ADComputer `
                                -Identity $DistinguishedName `
                                -Properties `
                                    Enabled,
                                    adminCount,
                                    UserAccountControl,
                                    SID,
                                    ObjectGUID,
                                    DistinguishedName,
                                    SamAccountName,
                                    Name `
                                -ErrorAction Stop
                    }

                    # =================================================
                    # GROUP
                    # =================================================

                    'Group' {

                        $Detail =
                            Get-ADGroup `
                                -Identity $DistinguishedName `
                                -Properties `
                                    adminCount,
                                    SID,
                                    ObjectGUID,
                                    DistinguishedName,
                                    SamAccountName,
                                    Name `
                                -ErrorAction Stop
                    }

                    # =================================================
                    # UNKNOWN
                    # =================================================

                    default {

                        $Detail =
                            Get-ADObject `
                                -Identity $DistinguishedName `
                                -Properties `
                                    Name,
                                    SamAccountName,
                                    ObjectClass,
                                    ObjectGUID,
                                    DistinguishedName,
                                    UserAccountControl,
                                    SID `
                                -ErrorAction Stop
                    }
                }
            }
            catch {

                Write-Verbose -Message (
                    'Unable to resolve member {0}: {1}' -f
                    $DistinguishedName,
                    $_.Exception.Message
                )

                $Detail = $null
            }
        }

        # ============================================================
        # APPLY RESOLVED PROPERTIES
        # ============================================================

        if (
            $null -ne $Detail
        ) {

            # --------------------------------------------------------
            # Name
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties['Name']
            ) {

                $Name =
                    [string]
                    $Detail.PSObject.Properties[
                        'Name'
                    ].Value
            }

            # --------------------------------------------------------
            # SamAccountName
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'SamAccountName'
                ]
            ) {

                $SamAccountName =
                    [string]
                    $Detail.PSObject.Properties[
                        'SamAccountName'
                    ].Value
            }

            # --------------------------------------------------------
            # DistinguishedName
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'DistinguishedName'
                ]
            ) {

                $DistinguishedName =
                    [string]
                    $Detail.PSObject.Properties[
                        'DistinguishedName'
                    ].Value
            }

            # --------------------------------------------------------
            # ObjectGUID
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'ObjectGUID'
                ]
            ) {

                try {

                    $ObjectGuid =
                        [guid]
                        $Detail.PSObject.Properties[
                            'ObjectGUID'
                        ].Value
                }
                catch {

                    Write-Verbose -Message `
                        'A resolved member has an invalid ObjectGUID.'
                }
            }

            # --------------------------------------------------------
            # ObjectClass
            # --------------------------------------------------------

            $DetailClasses = @()

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'ObjectClass'
                ]
            ) {

                $DetailClasses =
                    @(
                        $Detail.PSObject.Properties[
                            'ObjectClass'
                        ].Value
                    )
            }

            if (
                $DetailClasses -contains 'user'
            ) {

                $ObjectClass =
                    'User'
            }
            elseif (
                $DetailClasses -contains 'computer'
            ) {

                $ObjectClass =
                    'Computer'
            }
            elseif (
                $DetailClasses -contains 'group'
            ) {

                $ObjectClass =
                    'Group'
            }

            # --------------------------------------------------------
            # Enabled
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'Enabled'
                ] -and
                $null -ne
                $Detail.PSObject.Properties[
                    'Enabled'
                ].Value
            ) {

                $Enabled =
                    [bool]
                    $Detail.PSObject.Properties[
                        'Enabled'
                    ].Value
            }

            # --------------------------------------------------------
            # AdminCount
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'adminCount'
                ] -and
                $null -ne
                $Detail.PSObject.Properties[
                    'adminCount'
                ].Value
            ) {

                try {

                    $AdminCount =
                        [int]
                        $Detail.PSObject.Properties[
                            'adminCount'
                        ].Value
                }
                catch {

                    Write-Verbose -Message `
                        'A resolved member has an invalid adminCount.'
                }
            }

            # --------------------------------------------------------
            # UserAccountControl
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'UserAccountControl'
                ] -and
                $null -ne
                $Detail.PSObject.Properties[
                    'UserAccountControl'
                ].Value
            ) {

                try {

                    $UserAccountControl =
                        [int64]
                        $Detail.PSObject.Properties[
                            'UserAccountControl'
                        ].Value
                }
                catch {

                    Write-Verbose -Message `
                        'A resolved member has an invalid UserAccountControl.'
                }
            }

            # --------------------------------------------------------
            # PasswordNeverExpires
            #
            # Only meaningful for users.
            # --------------------------------------------------------

            if (
                $ObjectClass -eq 'User'
            ) {

                if (
                    $null -ne
                    $Detail.PSObject.Properties[
                        'PasswordNeverExpires'
                    ] -and
                    $null -ne
                    $Detail.PSObject.Properties[
                        'PasswordNeverExpires'
                    ].Value
                ) {

                    $PasswordNeverExpires =
                        [bool]
                        $Detail.PSObject.Properties[
                            'PasswordNeverExpires'
                        ].Value
                }
            }

            # --------------------------------------------------------
            # SID
            # --------------------------------------------------------

            if (
                $null -ne
                $Detail.PSObject.Properties[
                    'SID'
                ] -and
                $null -ne
                $Detail.PSObject.Properties[
                    'SID'
                ].Value
            ) {

                $MemberSid =
                    [string]
                    $Detail.PSObject.Properties[
                        'SID'
                    ].Value
            }

            # ========================================================
            # DERIVE PasswordNeverExpires FROM UAC
            #
            # DONT_EXPIRE_PASSWORD = 0x10000
            # ========================================================

            if (
                $null -eq $PasswordNeverExpires -and
                $ObjectClass -eq 'User' -and
                $null -ne $UserAccountControl
            ) {

                $PasswordNeverExpires =
                    (
                        (
                            $UserAccountControl `
                                -band [int64]0x10000
                        ) -ne 0
                    )
            }

            # ========================================================
            # DERIVE ENABLED FROM UAC
            #
            # ACCOUNTDISABLE = 0x2
            # ========================================================

            if (
                $null -eq $Enabled -and
                $null -ne $UserAccountControl
            ) {

                $Enabled =
                    (
                        (
                            $UserAccountControl `
                                -band [int64]0x2
                        ) -eq 0
                    )
            }
        }

        # ============================================================
        # CYCLE PROTECTION FOR MEMBER GROUP
        # ============================================================

        if (
            $ObjectClass -eq 'Group' -and
            -not [string]::IsNullOrWhiteSpace(
                $DistinguishedName
            ) -and
            $VisitedGroups.ContainsKey(
                $DistinguishedName
            )
        ) {

            Write-Verbose -Message (
                'Skipping already visited member group {0}.' -f
                $DistinguishedName
            )

            continue
        }

        # ============================================================
        # BUILD MEMBERSHIP PATH
        # ============================================================

        $CurrentPath = @(
            $MembershipPath + $GroupIdentity
        )

        $MembershipType =
            'Direct'

        if (
            $MembershipPath.Count -gt 0
        ) {

            $MembershipType =
                'Indirect'
        }

        # ============================================================
        # NORMALIZED MEMBER
        # ============================================================

        $NormalizedMember =
            [PSCustomObject][ordered]@{

                Name =
                    $Name

                SamAccountName =
                    $SamAccountName

                ObjectClass =
                    $ObjectClass

                ObjectGUID =
                    $ObjectGuid

                DistinguishedName =
                    $DistinguishedName

                Enabled =
                    $Enabled

                AdminCount =
                    $AdminCount

                PasswordNeverExpires =
                    $PasswordNeverExpires

                UserAccountControl =
                    $UserAccountControl

                MemberType =
                    $ObjectClass

                MembershipType =
                    $MembershipType

                MembershipPath =
                    $CurrentPath

                SID =
                    $MemberSid

                Resolved =
                    ($null -ne $Detail)
            }

        $NormalizedMember

        # ============================================================
        # RECURSIVE GROUP TRAVERSAL
        # ============================================================

        if (
            $ObjectClass -eq 'Group' -and
            -not [string]::IsNullOrWhiteSpace(
                $DistinguishedName
            )
        ) {

            Resolve-TechHubADGroupMembership `
                -GroupIdentity $DistinguishedName `
                -MembershipPath $CurrentPath `
                -VisitedGroups $VisitedGroups
        }
    }
}