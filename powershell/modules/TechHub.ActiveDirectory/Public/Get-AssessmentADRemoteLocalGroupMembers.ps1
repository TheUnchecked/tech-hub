#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteLocalGroupMembers {

    <#
    .SYNOPSIS
        Collects local group memberships from remote Windows computers.

    .DESCRIPTION
        Read-only remote assessment.

        Transport selection is delegated to:
            Invoke-AssessmentADRemoteCimQuery

        Transport order:
            1. WSMan
            2. DCOM

        The collector preserves the native Win32_Account identity
        information so that downstream classification can reliably
        distinguish:

            - Local accounts
            - Domain principals
            - Built-in principals
            - Well-known principals

        IMPORTANT:
        The collector does NOT classify the member.

        It only collects and normalizes the identity data.

    .PARAMETER ComputerName
        One or more remote Windows computers.

    .PARAMETER Credential
        Optional alternate credential.

    .PARAMETER UseSSL
        Requests the WSMan transport over HTTPS. Has no effect on the
        DCOM fallback, which does not use WSMan.

    .OUTPUTS
        ComputerName
        GroupName
        GroupMembers
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

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'DNSHostName',
            'CN',
            'Host',
            'Computer',
            'Name'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$UseSSL
    )

    process {

        Write-Verbose `
            "[$ComputerName] Collecting local group memberships."

        $queryResult = $null

        try {

            # ========================================================
            # REMOTE CIM QUERY
            # ========================================================

            $transportParams = @{
                ComputerName = $ComputerName
                UseSSL       = $UseSSL

                ScriptBlock = {

                    param($Session)

                    # ====================================================
                    # LOCAL GROUPS
                    # ====================================================

                    $groups = Get-CimInstance `
                        -CimSession $Session `
                        -ClassName Win32_Group `
                        -Filter 'LocalAccount = TRUE' `
                        -ErrorAction Stop

                    $results = foreach ($group in @($groups)) {

                        # ------------------------------------------------
                        # Member collection
                        # ------------------------------------------------

                        $memberObjects = @()

                        $memberStatus = 'Available'

                        try {

                            $members = Get-CimAssociatedInstance `
                                -CimSession $Session `
                                -InputObject $group `
                                -Association Win32_GroupUser `
                                -ResultClassName Win32_Account `
                                -ErrorAction Stop

                            $memberObjects = @(
                                $members |
                                    Sort-Object Domain, Name |
                                    ForEach-Object {

                                        $domain = $null
                                        $name = $null
                                        $sid = $null
                                        $localAccount = $null
                                        $accountType = $null

                                        # ====================================
                                        # DOMAIN
                                        # ====================================

                                        if (
                                            $_.PSObject.Properties['Domain'] -and
                                            $null -ne $_.Domain
                                        ) {

                                            $domain = [string]$_.Domain
                                        }

                                        # ====================================
                                        # NAME
                                        # ====================================

                                        if (
                                            $_.PSObject.Properties['Name'] -and
                                            $null -ne $_.Name
                                        ) {

                                            $name = [string]$_.Name
                                        }

                                        # ====================================
                                        # SID
                                        # ====================================

                                        if (
                                            $_.PSObject.Properties['SID'] -and
                                            $null -ne $_.SID
                                        ) {

                                            $sid = [string]$_.SID
                                        }

                                        # ====================================
                                        # LOCAL ACCOUNT
                                        #
                                        # Win32_Account exposes:
                                        #
                                        # LocalAccount = TRUE/FALSE
                                        #
                                        # This is much more reliable than
                                        # guessing from DOMAIN\NAME.
                                        # ====================================

                                        if (
                                            $_.PSObject.Properties['LocalAccount'] -and
                                            $null -ne $_.LocalAccount
                                        ) {

                                            try {
                                                $localAccount =
                                                    [bool]$_.LocalAccount
                                            }
                                            catch {
                                                $localAccount = $null
                                            }
                                        }

                                        # ====================================
                                        # ACCOUNT TYPE
                                        #
                                        # Win32_Account.Type can be useful
                                        # for additional downstream logic.
                                        # ====================================

                                        if (
                                            $_.PSObject.Properties['AccountType'] -and
                                            $null -ne $_.AccountType
                                        ) {

                                            try {
                                                $accountType =
                                                    [int]$_.AccountType
                                            }
                                            catch {
                                                $accountType = $null
                                            }
                                        }
                                        elseif (
                                            $_.PSObject.Properties['Type'] -and
                                            $null -ne $_.Type
                                        ) {

                                            try {
                                                $accountType =
                                                    [int]$_.Type
                                            }
                                            catch {
                                                $accountType = $null
                                            }
                                        }

                                        # ====================================
                                        # NORMALIZED DISPLAY NAME
                                        # ====================================

                                        $displayName = $null

                                        if (
                                            -not [string]::IsNullOrWhiteSpace(
                                                $domain
                                            ) -and
                                            -not [string]::IsNullOrWhiteSpace(
                                                $name
                                            )
                                        ) {

                                            $displayName = '{0}\{1}' -f `
                                                $domain,
                                                $name
                                        }
                                        elseif (
                                            -not [string]::IsNullOrWhiteSpace(
                                                $name
                                            )
                                        ) {

                                            $displayName = $name
                                        }

                                        # ====================================
                                        # RETURN NORMALIZED MEMBER
                                        # ====================================

                                        [PSCustomObject][ordered]@{

                                            # Original Windows identity
                                            Member = $displayName

                                            # Separate identity components
                                            Domain = $domain

                                            Name = $name

                                            # Security identifier
                                            SID = $sid

                                            # Native Win32 classification
                                            LocalAccount = $localAccount

                                            # Native account type when available
                                            AccountType = $accountType
                                        }
                                    }
                            )

                            if ($null -eq $memberObjects) {
                                $memberObjects = @()
                            }
                        }
                        catch {

                            $memberStatus = 'Partial'

                            $memberObjects = @()
                        }

                        # ====================================================
                        # GROUP RESULT
                        # ====================================================

                        [PSCustomObject][ordered]@{

                            ComputerName = $env:COMPUTERNAME

                            GroupName = [string]$group.Name

                            GroupMembers = @($memberObjects)

                            MemberStatus = $memberStatus
                        }
                    }

                    return @($results)
                }
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $transportParams.Credential = $Credential
            }

            $queryResult =
                Invoke-AssessmentADRemoteCimQuery @transportParams
        }
        catch {

            $queryResult = [PSCustomObject][ordered]@{

                ComputerName =
                    $ComputerName

                Transport =
                    'None'

                Status =
                    'NotAvailable'

                DataAvailability =
                    'NotAvailable'

                Data =
                    @()

                ErrorType =
                    'RemoteQueryError'

                ErrorMessage =
                    $_.Exception.Message

                IsReadOnly =
                    $true
            }
        }

        # ============================================================
        # TRANSPORT FAILURE
        # ============================================================

        if (
            $null -eq $queryResult -or
            $queryResult.Status -ne 'Available'
        ) {

            [PSCustomObject][ordered]@{

                ComputerName =
                    $ComputerName

                GroupName =
                    $null

                GroupMembers =
                    @()

                CollectionMethod =
                    'WMI'

                Transport =
                    if ($null -ne $queryResult) {
                        [string]$queryResult.Transport
                    }
                    else {
                        'None'
                    }

                Status =
                    'NotAvailable'

                DataAvailability =
                    'NotAvailable'

                ErrorType =
                    if ($null -ne $queryResult) {
                        $queryResult.ErrorType
                    }
                    else {
                        'RemoteQueryError'
                    }

                ErrorMessage =
                    if ($null -ne $queryResult) {
                        $queryResult.ErrorMessage
                    }
                    else {
                        'Remote query failed.'
                    }

                IsReadOnly =
                    $true
            }

            return
        }

        # ============================================================
        # NORMALIZE RESULTS
        # ============================================================

        foreach ($item in @($queryResult.Data)) {

            if ($null -eq $item) {
                continue
            }

            $members = @()

            if (
                $item.PSObject.Properties['GroupMembers'] -and
                $null -ne $item.GroupMembers
            ) {

                $members =
                    @($item.GroupMembers)
            }

            $memberStatus = 'Available'

            if (
                $item.PSObject.Properties['MemberStatus'] -and
                $item.MemberStatus
            ) {

                $memberStatus =
                    [string]$item.MemberStatus
            }

            [PSCustomObject][ordered]@{

                # IMPORTANT:
                # Always use the requested target.
                # Never use the local PowerShell session computer.

                ComputerName =
                    $ComputerName

                GroupName =
                    [string]$item.GroupName

                GroupMembers =
                    $members

                CollectionMethod =
                    'WMI'

                Transport =
                    [string]$queryResult.Transport

                Status =
                    if ($memberStatus -eq 'Partial') {
                        'Partial'
                    }
                    else {
                        'Available'
                    }

                DataAvailability =
                    'Available'

                ErrorType =
                    $null

                ErrorMessage =
                    $null

                IsReadOnly =
                    $true
            }
        }
    }
}