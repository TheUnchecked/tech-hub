#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADPrivilegedGroup {

    [CmdletBinding()]

    param (

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$GroupPatterns = @(),

        [Parameter()]
        [string[]]$ApprovedMemberPatterns = @(),

        [Parameter()]
        [string[]]$ExcludedMemberPatterns = @(),

        [Parameter()]
        [string[]]$PrivilegedGroupPatterns = @(),

        [Parameter()]
        [string[]]$ServiceAccountPatterns = @(),

        [Parameter()]
        [switch]$IncludeDisabled
    )

    # ============================================================
    # ASSESSMENT METADATA
    # ============================================================

    $AssessmentId = [guid]::NewGuid()

    $CheckId = 'AD-PRIVILEGED-GROUP'

    $CheckName = 'Privileged Groups'

    # ============================================================
    # DEFAULT PRIVILEGED GROUPS
    # ============================================================

    $DefaultGroups = @(
        'Domain Admins'
        'Enterprise Admins'
        'Schema Admins'
        'Administrators'
        'Account Operators'
        'Server Operators'
        'Backup Operators'
        'Domain Controllers'
    )

    $AnalysisPatterns = @(
        $DefaultGroups +
        $GroupPatterns
    )

    $PrivilegePatterns = @(
        $DefaultGroups +
        $PrivilegedGroupPatterns
    )

    # ============================================================
    # AD GROUP QUERY
    # ============================================================

    $GroupParameters = @{
        Filter     = '*'
        Properties = @(
            'Name'
            'SamAccountName'
            'DistinguishedName'
            'ObjectGUID'
            'ObjectClass'
        )
        ErrorAction = 'Stop'
    }

    if (
        -not [string]::IsNullOrWhiteSpace(
            $Server
        )
    ) {

        $GroupParameters.Server = $Server
    }

    if (
        -not [string]::IsNullOrWhiteSpace(
            $SearchBase
        )
    ) {

        $GroupParameters.SearchBase = $SearchBase
    }

    # ============================================================
    # DOMAIN CONTEXT
    # ============================================================

    $Domain = $null

    $Forest = $null

    $DomainController = $Server

    try {

        $ContextParameters = @{
            ErrorAction = 'Stop'
        }

        if (
            -not [string]::IsNullOrWhiteSpace(
                $Server
            )
        ) {

            $ContextParameters.Server = $Server
        }

        $DomainContext =
            Get-ADDomain @ContextParameters

        if (
            $null -ne $DomainContext
        ) {

            if (
                $null -ne
                $DomainContext.PSObject.Properties[
                    'DNSRoot'
                ]
            ) {

                $Domain =
                    [string]$DomainContext.DNSRoot
            }
        }
    }
    catch {

        Write-Verbose -Message (
            'Unable to collect domain context: {0}' -f
            $_.Exception.Message
        )
    }

    # ============================================================
    # FOREST CONTEXT
    # ============================================================

    try {

        $ContextParameters = @{
            ErrorAction = 'Stop'
        }

        if (
            -not [string]::IsNullOrWhiteSpace(
                $Server
            )
        ) {

            $ContextParameters.Server = $Server
        }

        $ForestContext =
            Get-ADForest @ContextParameters

        if (
            $null -ne $ForestContext
        ) {

            if (
                $null -ne
                $ForestContext.PSObject.Properties[
                    'Name'
                ]
            ) {

                $Forest =
                    [string]$ForestContext.Name
            }
        }
    }
    catch {

        Write-Verbose -Message (
            'Unable to collect forest context: {0}' -f
            $_.Exception.Message
        )
    }

    # ============================================================
    # QUERY PRIVILEGED GROUPS
    # ============================================================

    try {

        Write-Verbose -Message `
            'Querying Active Directory for privileged groups.'

        $Groups = @(
            Get-ADGroup @GroupParameters |
                Where-Object {

                    $Group = $_

                    $GroupValues = @()

                    foreach (
                        $PropertyName in @(
                            'Name'
                            'SamAccountName'
                            'DistinguishedName'
                        )
                    ) {

                        if (
                            $null -ne
                            $Group.PSObject.Properties[
                                $PropertyName
                            ]
                        ) {

                            $Value =
                                $Group.PSObject.Properties[
                                    $PropertyName
                                ].Value

                            if (
                                $null -ne $Value
                            ) {

                                $GroupValues +=
                                    [string]$Value
                            }
                        }
                    }

                    @(
                        $AnalysisPatterns |
                            Where-Object {

                                $Pattern = $_

                                @(
                                    $GroupValues |
                                        Where-Object {
                                            $_ -like $Pattern
                                        }
                                ).Count -gt 0
                            }
                    ).Count -gt 0
                }
        )
    }
    catch {

        Write-Error -ErrorRecord $_

        return
    }

    Write-Verbose -Message (
        'Found {0} configured privileged group(s).' -f
        $Groups.Count
    )

    # ============================================================
    # PROCESS GROUPS
    # ============================================================

    foreach (
        $Group in $Groups
    ) {

        # ========================================================
        # GROUP PROPERTIES
        # ========================================================

        $GroupName = $null

        $GroupDn = $null

        $GroupSamAccountName = $null

        $GroupGuid = $null

        if (
            $null -ne
            $Group.PSObject.Properties['Name']
        ) {

            $GroupName =
                [string]$Group.PSObject.Properties[
                    'Name'
                ].Value
        }

        if (
            $null -ne
            $Group.PSObject.Properties[
                'DistinguishedName'
            ]
        ) {

            $GroupDn =
                [string]$Group.PSObject.Properties[
                    'DistinguishedName'
                ].Value
        }

        if (
            $null -ne
            $Group.PSObject.Properties[
                'SamAccountName'
            ]
        ) {

            $GroupSamAccountName =
                [string]$Group.PSObject.Properties[
                    'SamAccountName'
                ].Value
        }

        if (
            $null -ne
            $Group.PSObject.Properties[
                'ObjectGUID'
            ]
        ) {

            try {

                $GroupGuid =
                    [guid]$Group.PSObject.Properties[
                        'ObjectGUID'
                    ].Value
            }
            catch {

                Write-Verbose -Message (
                    'Group [{0}] has an invalid ObjectGUID.' -f
                    $GroupName
                )
            }
        }

        # ========================================================
        # VALIDATE GROUP IDENTITY
        # ========================================================

        if (
            [string]::IsNullOrWhiteSpace(
                $GroupDn
            ) -or
            $GroupDn -eq 'string'
        ) {

            Write-Verbose -Message (
                'Skipping privileged group [{0}] because its DistinguishedName is invalid: [{1}]' -f
                $GroupName,
                $GroupDn
            )

            continue
        }

        # ========================================================
        # PRIVILEGED GROUP CLASSIFICATION
        # ========================================================

        $GroupIsPrivileged =
            @(
                $PrivilegePatterns |
                    Where-Object {

                        $GroupName -like $_ -or
                        $GroupDn -like $_
                    }
            ).Count -gt 0

        # ========================================================
        # GROUP MEMBERSHIP RESOLUTION
        # ========================================================

        $Visited = @{}

        Write-Verbose -Message (
            'Resolving membership for privileged group [{0}] [{1}].' -f
            $GroupName,
            $GroupDn
        )

        try {

            $Members = @(
                Resolve-TechHubADGroupMembership `
                    -GroupIdentity $GroupDn `
                    -VisitedGroups $Visited `
                    -Server $Server
            )
        }
        catch {

            Write-Verbose -Message (
                'Unable to resolve membership for group [{0}: {1}' -f
                $GroupName,
                $_.Exception.Message
            )

            $Members = @()
        }

        # ========================================================
        # EMPTY / UNREADABLE GROUP
        # ========================================================

        if (
            $Members.Count -eq 0
        ) {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'PrivilegedAccess' `
                -Title (
                    'Empty privileged group: {0}' -f
                    $GroupName
                ) `
                -Description `
                    'The configured privileged group has no readable members.' `
                -Severity 'Informational' `
                -Confidence 'Medium' `
                -Status 'NotApplicable' `
                -AffectedObject (
                    [PSCustomObject][ordered]@{
                        Name        = $GroupName
                        ObjectClass = 'Group'
                        Enabled     = $null
                    }
                ) `
                -ObjectType 'Group' `
                -DistinguishedName $GroupDn `
                -SamAccountName $GroupSamAccountName `
                -ObjectGuid $GroupGuid `
                -Evidence (
                    [PSCustomObject][ordered]@{
                        PrivilegedGroup       = $GroupName
                        PrivilegedGroupDN     = $GroupDn
                        MemberName            = $null
                        MemberSamAccountName  = $null
                        MemberObjectType      = $null
                        MembershipType        = $null
                        MembershipPath        = @()
                        Enabled               = $null
                        AdminCount            = $null
                        PasswordNeverExpires  = $null
                        Approved              = $false
                        Excluded              = $false
                    }
                ) `
                -Risk `
                    'An empty privileged group is informational and should be reviewed for lifecycle and ownership.' `
                -Recommendation `
                    'Confirm that the group is still required and has an owner; remove or archive it through a separately reviewed administrative process if appropriate.' `
                -References @(
                    'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
                ) `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        # ========================================================
        # PROCESS MEMBERS
        # ========================================================

        foreach (
            $Member in $Members
        ) {

            # ====================================================
            # SAFE PROPERTY ACCESS
            # ====================================================

            $MemberName = $null

            $MemberSamAccountName = $null

            $MemberDn = $null

            $MemberObjectClass = 'Unknown'

            $MemberEnabled = $null

            $MemberAdminCount = $null

            $MemberPasswordNeverExpires = $null

            $MemberMembershipType = 'Direct'

            $MemberMembershipPath = @()

            $MemberObjectGuid = $null

            $MemberSid = $null

            $MemberResolved = $false

            # ----------------------------------------------------
            # Name
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties['Name']
            ) {

                $MemberName =
                    [string]$Member.PSObject.Properties[
                        'Name'
                    ].Value
            }

            # ----------------------------------------------------
            # SamAccountName
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'SamAccountName'
                ]
            ) {

                $MemberSamAccountName =
                    [string]$Member.PSObject.Properties[
                        'SamAccountName'
                    ].Value
            }

            # ----------------------------------------------------
            # DistinguishedName
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'DistinguishedName'
                ]
            ) {

                $MemberDn =
                    [string]$Member.PSObject.Properties[
                        'DistinguishedName'
                    ].Value
            }

            # ----------------------------------------------------
            # ObjectClass
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'ObjectClass'
                ]
            ) {

                $MemberObjectClass =
                    [string]$Member.PSObject.Properties[
                        'ObjectClass'
                    ].Value
            }

            # ----------------------------------------------------
            # Enabled
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'Enabled'
                ]
            ) {

                $Value =
                    $Member.PSObject.Properties[
                        'Enabled'
                    ].Value

                if (
                    $null -ne $Value
                ) {

                    $MemberEnabled =
                        [bool]$Value
                }
            }

            # ----------------------------------------------------
            # AdminCount
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'AdminCount'
                ]
            ) {

                $Value =
                    $Member.PSObject.Properties[
                        'AdminCount'
                    ].Value

                if (
                    $null -ne $Value
                ) {

                    try {

                        $MemberAdminCount =
                            [int]$Value
                    }
                    catch {

                        $MemberAdminCount = $null
                    }
                }
            }

            # ----------------------------------------------------
            # PasswordNeverExpires
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'PasswordNeverExpires'
                ]
            ) {

                $Value =
                    $Member.PSObject.Properties[
                        'PasswordNeverExpires'
                    ].Value

                if (
                    $null -ne $Value
                ) {

                    $MemberPasswordNeverExpires =
                        [bool]$Value
                }
            }

            # ----------------------------------------------------
            # MembershipType
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'MembershipType'
                ]
            ) {

                $Value =
                    $Member.PSObject.Properties[
                        'MembershipType'
                    ].Value

                if (
                    -not [string]::IsNullOrWhiteSpace(
                        [string]$Value
                    )
                ) {

                    $MemberMembershipType =
                        [string]$Value
                }
            }

            # ----------------------------------------------------
            # MembershipPath
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'MembershipPath'
                ]
            ) {

                $MemberMembershipPath =
                    @(
                        $Member.PSObject.Properties[
                            'MembershipPath'
                        ].Value
                    )
            }

            # ----------------------------------------------------
            # ObjectGUID
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'ObjectGUID'
                ]
            ) {

                try {

                    $MemberObjectGuid =
                        [guid]$Member.PSObject.Properties[
                            'ObjectGUID'
                        ].Value
                }
                catch {

                    $MemberObjectGuid = $null
                }
            }

            # ----------------------------------------------------
            # SID
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'SID'
                ]
            ) {

                $MemberSid =
                    [string]$Member.PSObject.Properties[
                        'SID'
                    ].Value
            }

            # ----------------------------------------------------
            # Resolved
            # ----------------------------------------------------

            if (
                $null -ne
                $Member.PSObject.Properties[
                    'Resolved'
                ]
            ) {

                $MemberResolved =
                    [bool]$Member.PSObject.Properties[
                        'Resolved'
                    ].Value
            }

            # ====================================================
            # DISABLED MEMBER
            # ====================================================

            if (
                $MemberEnabled -eq $false -and
                -not $IncludeDisabled
            ) {

                Write-Verbose -Message (
                    'Skipping disabled member {0}; use -IncludeDisabled to report it.' -f
                    $MemberName
                )

                continue
            }

            # ====================================================
            # IDENTITY VALUES
            # ====================================================

            $IdentityValues = @(
                $MemberName
                $MemberSamAccountName
                $MemberDn
                $MemberSid
            ) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace(
                        [string]$_
                    )
                }

            # ====================================================
            # APPROVED
            # ====================================================

            $Approved =
                @(
                    $ApprovedMemberPatterns |
                        Where-Object {

                            $Pattern = $_

                            @(
                                $IdentityValues |
                                    Where-Object {
                                        $_ -like $Pattern
                                    }
                            ).Count -gt 0
                        }
                ).Count -gt 0

            # ====================================================
            # EXCLUDED
            # ====================================================

            $Excluded =
                @(
                    $ExcludedMemberPatterns |
                        Where-Object {

                            $Pattern = $_

                            @(
                                $IdentityValues |
                                    Where-Object {
                                        $_ -like $Pattern
                                    }
                            ).Count -gt 0
                        }
                ).Count -gt 0

            # ====================================================
            # SERVICE ACCOUNT
            # ====================================================

            $IsServiceAccount = $false

            if (
                $ServiceAccountPatterns.Count -gt 0
            ) {

                $ServiceAccountValues = @(
                    $MemberName
                    $MemberSamAccountName
                )

                $IsServiceAccount =
                    @(
                        $ServiceAccountPatterns |
                            Where-Object {

                                $Pattern = $_

                                @(
                                    $ServiceAccountValues |
                                        Where-Object {
                                            $_ -like $Pattern
                                        }
                                ).Count -gt 0
                            }
                    ).Count -gt 0
            }

            # ====================================================
            # SEVERITY
            # ====================================================

            $Severity = 'Low'

            $Status = 'Finding'

            if (
                $Excluded -or
                $Approved
            ) {

                $Severity = 'Informational'

                $Status = 'NotApplicable'
            }
            elseif (
                $GroupIsPrivileged -and
                $MemberMembershipType -eq 'Indirect' -and
                $MemberObjectClass -ne 'Group' -and
                $ApprovedMemberPatterns.Count -gt 0
            ) {

                $Severity = 'Critical'
            }
            elseif (
                $GroupIsPrivileged -and
                (
                    $IsServiceAccount -or
                    $MemberAdminCount -eq 1
                )
            ) {

                $Severity = 'High'
            }
            elseif (
                $GroupIsPrivileged -and
                $ApprovedMemberPatterns.Count -gt 0
            ) {

                $Severity = 'High'
            }
            elseif (
                $MemberEnabled -eq $false -or
                $MemberPasswordNeverExpires -eq $true -or
                (
                    $MemberMembershipType -eq 'Indirect' -and
                    $MemberObjectClass -eq 'Group'
                )
            ) {

                $Severity = 'Medium'
            }

            # ====================================================
            # EVIDENCE
            # ====================================================

            $Evidence =
                [PSCustomObject][ordered]@{

                    PrivilegedGroup =
                        $GroupName

                    PrivilegedGroupDN =
                        $GroupDn

                    MemberName =
                        $MemberName

                    MemberSamAccountName =
                        $MemberSamAccountName

                    MemberObjectType =
                        $MemberObjectClass

                    MembershipType =
                        $MemberMembershipType

                    MembershipPath =
                        $MemberMembershipPath

                    Enabled =
                        $MemberEnabled

                    AdminCount =
                        $MemberAdminCount

                    PasswordNeverExpires =
                        $MemberPasswordNeverExpires

                    Approved =
                        $Approved

                    Excluded =
                        $Excluded

                    IsServiceAccount =
                        $IsServiceAccount

                    PrivilegedGroupMembership =
                        @($GroupName)
                }

            # ====================================================
            # FINDING
            # ====================================================

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'PrivilegedAccess' `
                -Title (
                    'Privileged group membership: {0} in {1}' -f
                    $MemberName,
                    $GroupName
                ) `
                -Description `
                    'The member is included in a configured privileged Active Directory group.' `
                -Severity $Severity `
                -Confidence $(
                    if ($MemberResolved) {
                        'High'
                    }
                    else {
                        'Medium'
                    }
                ) `
                -Status $Status `
                -AffectedObject (
                    [PSCustomObject][ordered]@{
                        Name        = $MemberName
                        ObjectClass = $MemberObjectClass
                        Enabled     = $MemberEnabled
                    }
                ) `
                -ObjectType $MemberObjectClass `
                -DistinguishedName $MemberDn `
                -SamAccountName $MemberSamAccountName `
                -ObjectGuid $MemberObjectGuid `
                -Evidence $Evidence `
                -Risk `
                    'Privileged group membership increases the impact of compromise; the risk depends on authorization, scope, nesting, and account controls.' `
                -Recommendation `
                    'Validate ownership and business need, apply least privilege, review nesting, and remove unneeded membership through a separately reviewed administrative process.' `
                -References @(
                    'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
                ) `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController
        }
    }
}