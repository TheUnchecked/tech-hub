#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteLocalGroups {
    <#
    .SYNOPSIS
        Collects local group membership from selected Active Directory
        computer targets.

    .DESCRIPTION
        Uses Get-AssessmentADRemoteTargets for target discovery and
        Get-AssessmentADRemoteLocalGroupMembers for remote collection.

        Target selection supports:

            All
            Server
            Client
            DomainController
            SearchBase

        The collector returns every discovered local group and every
        member contained in that group.

        No account names are hardcoded or filtered during collection.

        This function is read-only.

    .PARAMETER Provider
        Active Directory assessment provider.

    .PARAMETER TargetType
        Target selection mode.

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

        # ========================================================
        # TARGET DISCOVERY
        # ========================================================

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

                    ComputerName = $Name

                    TargetType = 'Unknown'

                    Enabled = $null

                    DistinguishedName = $null
                }
            }
        }
        else {

            $TargetParameters = @{
                Provider = $Provider
                TargetType = $TargetType
                ErrorAction = 'Stop'
            }

            if (
                -not [string]::IsNullOrWhiteSpace($SearchBase)
            ) {

                $TargetParameters.SearchBase = $SearchBase
            }

            if ($IncludeDisabled) {

                $TargetParameters.IncludeDisabled = $true
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

        # ========================================================
        # REMOTE LOCAL GROUP COLLECTION
        # ========================================================

        foreach ($Target in $Targets) {

            $Name = [string]$Target.ComputerName

            if (
                [string]::IsNullOrWhiteSpace($Name)
            ) {
                continue
            }

            Write-Verbose `
                "[$Name] Collecting local groups and members."

            try {

                $LocalGroups = @(
                    Get-AssessmentADRemoteLocalGroupMembers `
                        -ComputerName $Name `
                        -ErrorAction Stop
                )

                if ($LocalGroups.Count -eq 0) {

                    [PSCustomObject][ordered]@{

                        ComputerName =
                            $Name

                        TargetType =
                            [string]$Target.TargetType

                        GroupName =
                            $null

                        Member =
                            $null

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

                # =================================================
                # FLATTEN GROUP MEMBERS
                #
                # One output object per member.
                # =================================================

                foreach ($Group in $LocalGroups) {

                    $GroupName =
                        [string]$Group.GroupName

                    $Members = @(
                        $Group.GroupMembers
                    )

                    # ---------------------------------------------
                    # Empty group
                    # ---------------------------------------------

                    if ($Members.Count -eq 0) {

                        [PSCustomObject][ordered]@{

                            ComputerName =
                                $Name

                            TargetType =
                                [string]$Target.TargetType

                            GroupName =
                                $GroupName

                            Member =
                                $null

                            CollectionMethod =
                                $Group.CollectionMethod

                            Transport =
                                $Group.Transport

                            Status =
                                $Group.Status

                            DataAvailability =
                                $Group.DataAvailability

                            ErrorType =
                                $Group.ErrorType

                            ErrorMessage =
                                $Group.ErrorMessage

                            IsReadOnly =
                                $true
                        }

                        continue
                    }

                    # ---------------------------------------------
                    # One record per member
                    # ---------------------------------------------

                    foreach ($Member in $Members) {

                        if (
                            [string]::IsNullOrWhiteSpace(
                                [string]$Member
                            )
                        ) {
                            continue
                        }

                        [PSCustomObject][ordered]@{

                            ComputerName =
                                $Name

                            TargetType =
                                [string]$Target.TargetType

                            GroupName =
                                $GroupName

                            Member =
                                [string]$Member

                            CollectionMethod =
                                $Group.CollectionMethod

                            Transport =
                                $Group.Transport

                            Status =
                                $Group.Status

                            DataAvailability =
                                $Group.DataAvailability

                            ErrorType =
                                $Group.ErrorType

                            ErrorMessage =
                                $Group.ErrorMessage

                            IsReadOnly =
                                $true
                        }
                    }
                }
            }
            catch {

                Write-Verbose `
                    "[$Name] Local group collection failed: $($_.Exception.Message)"

                [PSCustomObject][ordered]@{

                    ComputerName =
                        $Name

                    TargetType =
                        [string]$Target.TargetType

                    GroupName =
                        $null

                    Member =
                        $null

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