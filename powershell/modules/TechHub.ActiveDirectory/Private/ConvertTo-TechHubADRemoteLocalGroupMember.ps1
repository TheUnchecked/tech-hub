#Requires -Version 5.1

Set-StrictMode -Version Latest

function ConvertTo-TechHubADRemoteLocalGroupMember {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [object]$InputObject
    )

    # ============================================================
    # GROUP CONTEXT
    # ============================================================

    $ComputerName = [string]$InputObject.ComputerName
    $GroupName = [string]$InputObject.GroupName

    # ============================================================
    # GROUP PROPERTIES
    # ============================================================

    $TargetType = $null

    if ($InputObject.PSObject.Properties['TargetType']) {
        $TargetType = [string]$InputObject.TargetType
    }

    $CollectionMethod = $null

    if ($InputObject.PSObject.Properties['CollectionMethod']) {
        $CollectionMethod = [string]$InputObject.CollectionMethod
    }

    $Transport = $null

    if ($InputObject.PSObject.Properties['Transport']) {
        $Transport = [string]$InputObject.Transport
    }

    $Status = $null

    if ($InputObject.PSObject.Properties['Status']) {
        $Status = [string]$InputObject.Status
    }

    $DataAvailability = $null

    if ($InputObject.PSObject.Properties['DataAvailability']) {
        $DataAvailability = [string]$InputObject.DataAvailability
    }

    $ErrorType = $null

    if ($InputObject.PSObject.Properties['ErrorType']) {
        $ErrorType = [string]$InputObject.ErrorType
    }

    $ErrorMessage = $null

    if ($InputObject.PSObject.Properties['ErrorMessage']) {
        $ErrorMessage = [string]$InputObject.ErrorMessage
    }

    # ============================================================
    # GROUP MEMBERS
    # ============================================================

    $GroupMembers = @()

    if (
        $InputObject.PSObject.Properties['GroupMembers'] -and
        $null -ne $InputObject.GroupMembers
    ) {
        $GroupMembers = @($InputObject.GroupMembers)
    }

    # ============================================================
    # ONE RESULT PER MEMBER
    # ============================================================

    foreach ($MemberObject in $GroupMembers) {

        if ($null -eq $MemberObject) {
            continue
        }

        # ========================================================
        # MEMBER
        # ========================================================

        $Member = $null

        if (
            $MemberObject.PSObject.Properties['Member'] -and
            $null -ne $MemberObject.Member
        ) {

            $Member = [string]$MemberObject.Member
        }
        else {

            $Domain = $null
            $Name = $null

            if ($MemberObject.PSObject.Properties['Domain']) {
                $Domain = [string]$MemberObject.Domain
            }

            if ($MemberObject.PSObject.Properties['Name']) {
                $Name = [string]$MemberObject.Name
            }

            if (
                -not [string]::IsNullOrWhiteSpace($Domain) -and
                -not [string]::IsNullOrWhiteSpace($Name)
            ) {

                $Member = '{0}\{1}' -f $Domain, $Name
            }
            elseif (
                -not [string]::IsNullOrWhiteSpace($Name)
            ) {

                $Member = $Name
            }
        }

        if ([string]::IsNullOrWhiteSpace($Member)) {
            continue
        }

        # ========================================================
        # MEMBER ATTRIBUTES
        # ========================================================

        $Domain = $null

        if ($MemberObject.PSObject.Properties['Domain']) {
            $Domain = [string]$MemberObject.Domain
        }

        $Name = $null

        if ($MemberObject.PSObject.Properties['Name']) {
            $Name = [string]$MemberObject.Name
        }

        $SID = $null

        if ($MemberObject.PSObject.Properties['SID']) {
            $SID = [string]$MemberObject.SID
        }

        $LocalAccount = $false

        if (
            $MemberObject.PSObject.Properties['LocalAccount'] -and
            $null -ne $MemberObject.LocalAccount
        ) {

            $LocalAccount = [bool]$MemberObject.LocalAccount
        }

        $AccountType = $null

        if ($MemberObject.PSObject.Properties['AccountType']) {
            $AccountType = $MemberObject.AccountType
        }

        # ========================================================
        # CLASSIFICATION
        # ========================================================

        $MemberType =
            Get-TechHubADRemoteLocalGroupMemberClassification `
                -ComputerName $ComputerName `
                -GroupName $GroupName `
                -Member $Member `
                -SID $SID `
                -LocalAccount $LocalAccount

        # ========================================================
        # OUTPUT
        # ========================================================

        [PSCustomObject][ordered]@{

            ComputerName = $ComputerName

            TargetType = $TargetType

            GroupName = $GroupName

            Member = $Member

            Domain = $Domain

            Name = $Name

            SID = $SID

            LocalAccount = $LocalAccount

            AccountType = $AccountType

            MemberType = $MemberType

            CollectionMethod = $CollectionMethod

            Transport = $Transport

            Status = $Status

            DataAvailability = $DataAvailability

            ErrorType = $ErrorType

            ErrorMessage = $ErrorMessage

            IsReadOnly = $true
        }
    }
}