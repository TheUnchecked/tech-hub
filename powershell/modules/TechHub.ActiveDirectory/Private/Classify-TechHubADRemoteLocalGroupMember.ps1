#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteLocalGroups {

    <#
    .SYNOPSIS
        Collects and classifies local group memberships from
        selected Active Directory computer targets.

    .DESCRIPTION
        Read-only remote assessment.

        Target discovery:
            Get-AssessmentADRemoteTargets

        Target OS enrichment:
            Get-AssessmentADRemoteOSInfo

        Remote local group collection:
            Get-AssessmentADRemoteLocalGroupMembers

        Member classification:
            Get-TechHubADRemoteLocalGroupMemberClassification

        The collector returns every discovered local group and
        every member contained in that group.

        Each member is returned as a separate normalized object.

        No account names are hardcoded or filtered during collection.

    .PARAMETER Provider
        Active Directory assessment provider.

    .PARAMETER TargetType
        Target selection mode.

        Valid values:
            All
            Server
            Client
            DomainController

    .PARAMETER SearchBase
        Optional Active Directory OU/container Distinguished Name.

    .PARAMETER IncludeDisabled
        Includes disabled computer accounts.

    .PARAMETER ComputerName
        Optional explicit computer names.

        When specified, AD target discovery is bypassed.

    .OUTPUTS
        ComputerName
        TargetType
        GroupName
        Member
        Domain
        Name
        SID
        LocalAccount
        AccountType
        MemberType
        CollectionMethod
        Transport
        Status
        DataAvailability
        ErrorType
        ErrorMessage
        IsReadOnly
    #>

    [CmdletBinding()]
    param(

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $Provider,

        [Parameter()]
        [ValidateSet(
            'All',
            'Server',
            'Client',
            'DomainController'
        )]
        [string]$TargetType = 'All',

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [string[]]$ComputerName
    )

    begin {

        Write-Verbose `
            "Starting remote local group assessment. TargetType=$TargetType"

        if (
            -not [string]::IsNullOrWhiteSpace($SearchBase)
        ) {

            Write-Verbose `
                "Using SearchBase: $SearchBase"
        }
    }

    process {

        # ============================================================
        # 1. TARGET DISCOVERY
        # ============================================================

        $Targets = @()

        if (
            $PSBoundParameters.ContainsKey('ComputerName') -and
            $ComputerName.Count -gt 0
        ) {

            Write-Verbose `
                'Explicit computer names supplied. AD target discovery will be bypassed.'

            foreach ($Name in $ComputerName) {

                if (
                    [string]::IsNullOrWhiteSpace($Name)
                ) {
                    continue
                }

                $Targets += [PSCustomObject][ordered]@{

                    ComputerName =
                        $Name

                    TargetType =
                        'Unknown'

                    Enabled =
                        $null

                    DistinguishedName =
                        $null
                }
            }
        }
        else {

            $TargetParameters = @{

                Provider =
                    $Provider

                TargetType =
                    $TargetType

                ErrorAction =
                    'Stop'
            }

            if (
                -not [string]::IsNullOrWhiteSpace($SearchBase)
            ) {

                $TargetParameters.SearchBase =
                    $SearchBase
            }

            if ($IncludeDisabled) {

                $TargetParameters.IncludeDisabled =
                    $true
            }

            $Targets = @(
                Get-AssessmentADRemoteTargets @TargetParameters
            )
        }

        if ($Targets.Count -eq 0) {

            Write-Verbose `
                'No remote assessment targets were discovered.'

            return
        }

        Write-Verbose `
            "Remote targets selected: $($Targets.Count)"

        # ============================================================
        # 2. TARGET PROCESSING
        # ============================================================

        foreach ($Target in $Targets) {

            $ComputerNameValue =
                [string]$Target.ComputerName

            if (
                [string]::IsNullOrWhiteSpace(
                    $ComputerNameValue
                )
            ) {
                continue
            }

            # ========================================================
            # 2.1 TARGET TYPE ENRICHMENT
            #
            # AD discovery does not reliably contain OperatingSystem
            # in the current provider result.
            #
            # Therefore TargetType is determined remotely from
            # Win32_OperatingSystem / ProductType.
            # ========================================================

            $ResolvedTargetType =
                'Unknown'

            try {

                Write-Verbose `
                    "[$ComputerNameValue] Resolving target type through remote OS information."

                $OSInfo =
                    Get-AssessmentADRemoteOSInfo `
                        -ComputerName $ComputerNameValue `
                        -ErrorAction Stop

                if (
                    $null -ne $OSInfo -and
                    $OSInfo.Status -eq 'Available' -and
                    -not [string]::IsNullOrWhiteSpace(
                        [string]$OSInfo.TargetType
                    )
                ) {

                    $ResolvedTargetType =
                        [string]$OSInfo.TargetType

                    Write-Verbose `
                        "[$ComputerNameValue] TargetType='$ResolvedTargetType'."
                }
                else {

                    Write-Verbose `
                        "[$ComputerNameValue] Target type could not be resolved. Using Unknown."
                }
            }
            catch {

                Write-Verbose `
                    "[$ComputerNameValue] Target type enrichment failed: $($_.Exception.Message)"

                $ResolvedTargetType =
                    'Unknown'
            }

            # ========================================================
            # 2.2 REMOTE LOCAL GROUP COLLECTION
            # ========================================================

            Write-Verbose `
                "[$ComputerNameValue] Collecting local groups and members."

            try {

                $LocalGroups = @(
                    Get-AssessmentADRemoteLocalGroupMembers `
                        -ComputerName $ComputerNameValue `
                        -ErrorAction Stop
                )

                if ($LocalGroups.Count -eq 0) {

                    [PSCustomObject][ordered]@{

                        ComputerName =
                            $ComputerNameValue

                        TargetType =
                            $ResolvedTargetType

                        GroupName =
                            $null

                        Member =
                            $null

                        Domain =
                            $null

                        Name =
                            $null

                        SID =
                            $null

                        LocalAccount =
                            $null

                        AccountType =
                            $null

                        MemberType =
                            'Unknown'

                        CollectionMethod =
                            $null

                        Transport =
                            $null

                        Status =
                            'NotAvailable'

                        DataAvailability =
                            'NotAvailable'

                        ErrorType =
                            'NoLocalGroupData'

                        ErrorMessage =
                            'No local group data was returned.'

                        IsReadOnly =
                            $true
                    }

                    continue
                }

                # ====================================================
                # 3. FLATTEN GROUP MEMBERS
                #
                # GroupMembers contains structured objects:
                #
                # Member
                # Domain
                # Name
                # SID
                # LocalAccount
                # AccountType
                #
                # One output object is created per member.
                # ====================================================

                foreach ($Group in $LocalGroups) {

                    if ($null -eq $Group) {
                        continue
                    }

                    $GroupName =
                        [string]$Group.GroupName

                    $Members = @()

                    if (
                        $Group.PSObject.Properties['GroupMembers'] -and
                        $null -ne $Group.GroupMembers
                    ) {

                        $Members = @(
                            $Group.GroupMembers
                        )
                    }

                    # =================================================
                    # 3.1 EMPTY GROUP
                    # =================================================

                    if ($Members.Count -eq 0) {

                        [PSCustomObject][ordered]@{

                            ComputerName =
                                $ComputerNameValue

                            TargetType =
                                $ResolvedTargetType

                            GroupName =
                                $GroupName

                            Member =
                                $null

                            Domain =
                                $null

                            Name =
                                $null

                            SID =
                                $null

                            LocalAccount =
                                $null

                            AccountType =
                                $null

                            MemberType =
                                'Unknown'

                            CollectionMethod =
                                [string]$Group.CollectionMethod

                            Transport =
                                [string]$Group.Transport

                            Status =
                                [string]$Group.Status

                            DataAvailability =
                                [string]$Group.DataAvailability

                            ErrorType =
                                [string]$Group.ErrorType

                            ErrorMessage =
                                [string]$Group.ErrorMessage

                            IsReadOnly =
                                $true
                        }

                        continue
                    }

                    # =================================================
                    # 3.2 ONE RECORD PER MEMBER
                    # =================================================

                    foreach ($MemberObject in $Members) {

                        if ($null -eq $MemberObject) {
                            continue
                        }

                        # ---------------------------------------------
                        # MEMBER
                        # ---------------------------------------------

                        $MemberValue =
                            $null

                        if (
                            $MemberObject.PSObject.Properties['Member']
                        ) {

                            $MemberValue =
                                [string]$MemberObject.Member
                        }
                        else {

                            $MemberValue =
                                [string]$MemberObject
                        }

                        if (
                            [string]::IsNullOrWhiteSpace(
                                $MemberValue
                            )
                        ) {
                            continue
                        }

                        # ---------------------------------------------
                        # DOMAIN
                        # ---------------------------------------------

                        $Domain =
                            $null

                        if (
                            $MemberObject.PSObject.Properties['Domain']
                        ) {

                            $Domain =
                                [string]$MemberObject.Domain
                        }

                        # ---------------------------------------------
                        # ACCOUNT NAME
                        # ---------------------------------------------

                        $Name =
                            $null

                        if (
                            $MemberObject.PSObject.Properties['Name']
                        ) {

                            $Name =
                                [string]$MemberObject.Name
                        }

                        # ---------------------------------------------
                        # SID
                        # ---------------------------------------------

                        $SID =
                            $null

                        if (
                            $MemberObject.PSObject.Properties['SID']
                        ) {

                            $SID =
                                [string]$MemberObject.SID
                        }

                        # ---------------------------------------------
                        # LOCAL ACCOUNT
                        # ---------------------------------------------

                        $LocalAccount =
                            $false

                        if (
                            $MemberObject.PSObject.Properties['LocalAccount']
                        ) {

                            if (
                                $null -ne
                                $MemberObject.LocalAccount
                            ) {

                                $LocalAccount =
                                    [bool]$MemberObject.LocalAccount
                            }
                        }

                        # ---------------------------------------------
                        # ACCOUNT TYPE
                        # ---------------------------------------------

                        $AccountType =
                            $null

                        if (
                            $MemberObject.PSObject.Properties['AccountType']
                        ) {

                            $AccountType =
                                $MemberObject.AccountType
                        }

                        # ---------------------------------------------
                        # MEMBER CLASSIFICATION
                        # ---------------------------------------------

                        $MemberType =
                            Get-TechHubADRemoteLocalGroupMemberClassification `
                                -ComputerName $ComputerNameValue `
                                -GroupName $GroupName `
                                -Member $MemberValue `
                                -SID $SID `
                                -LocalAccount $LocalAccount

                        # ---------------------------------------------
                        # NORMALIZED OUTPUT
                        # ---------------------------------------------

                        [PSCustomObject][ordered]@{

                            ComputerName =
                                $ComputerNameValue

                            TargetType =
                                $ResolvedTargetType

                            GroupName =
                                $GroupName

                            Member =
                                $MemberValue

                            Domain =
                                $Domain

                            Name =
                                $Name

                            SID =
                                $SID

                            LocalAccount =
                                $LocalAccount

                            AccountType =
                                $AccountType

                            MemberType =
                                $MemberType

                            CollectionMethod =
                                [string]$Group.CollectionMethod

                            Transport =
                                [string]$Group.Transport

                            Status =
                                [string]$Group.Status

                            DataAvailability =
                                [string]$Group.DataAvailability

                            ErrorType =
                                [string]$Group.ErrorType

                            ErrorMessage =
                                [string]$Group.ErrorMessage

                            IsReadOnly =
                                $true
                        }
                    }
                }
            }
            catch {

                Write-Verbose `
                    "[$ComputerNameValue] Local group collection failed: $($_.Exception.Message)"

                [PSCustomObject][ordered]@{

                    ComputerName =
                        $ComputerNameValue

                    TargetType =
                        $ResolvedTargetType

                    GroupName =
                        $null

                    Member =
                        $null

                    Domain =
                        $null

                    Name =
                        $null

                    SID =
                        $null

                    LocalAccount =
                        $null

                    AccountType =
                        $null

                    MemberType =
                        'Unknown'

                    CollectionMethod =
                        'None'

                    Transport =
                        'None'

                    Status =
                        'NotAvailable'

                    DataAvailability =
                        'NotAvailable'

                    ErrorType =
                        'LocalGroupCollectionError'

                    ErrorMessage =
                        $_.Exception.Message

                    IsReadOnly =
                        $true
                }
            }
        }
    }
}