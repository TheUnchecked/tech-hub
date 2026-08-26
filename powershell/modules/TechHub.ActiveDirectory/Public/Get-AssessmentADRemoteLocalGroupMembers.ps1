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

        The collector itself remains transport-agnostic.

    .PARAMETER ComputerName
        One or more remote Windows computers.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName
        GroupName
        GroupMembers
        CollectionMethod
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
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        Write-Verbose "[$ComputerName] Collecting local group memberships."

        $queryResult = $null

        try {

            $transportParams = @{
                ComputerName = $ComputerName
                ScriptBlock  = {
                    param($Session)

                    $groups = Get-CimInstance `
                        -CimSession $Session `
                        -ClassName Win32_Group `
                        -Filter 'LocalAccount = TRUE' `
                        -ErrorAction Stop

                    $results = foreach ($group in @($groups)) {

                        $memberNames = @()

                        try {

                            $members = Get-CimAssociatedInstance `
                                -CimSession $Session `
                                -InputObject $group `
                                -Association Win32_GroupUser `
                                -ResultClassName Win32_Account `
                                -ErrorAction Stop

                            $memberNames = @(
                                $members |
                                    Sort-Object Domain, Name |
                                    ForEach-Object {

                                        if (
                                            -not [string]::IsNullOrWhiteSpace(
                                                [string]$_.Domain
                                            ) -and
                                            -not [string]::IsNullOrWhiteSpace(
                                                [string]$_.Name
                                            )
                                        ) {
                                            '{0}\{1}' -f `
                                                $_.Domain,
                                                $_.Name
                                        }
                                        elseif (
                                            -not [string]::IsNullOrWhiteSpace(
                                                [string]$_.Name
                                            )
                                        ) {
                                            [string]$_.Name
                                        }
                                    }
                            )

                            $memberStatus = 'Available'
                        }
                        catch {

                            $memberStatus = 'Partial'
                        }

                        [PSCustomObject][ordered]@{

                            ComputerName = $env:COMPUTERNAME

                            GroupName = [string]$group.Name

                            GroupMembers = $memberNames

                            MemberStatus = $memberStatus
                        }
                    }

                    return @($results)
                }
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $transportParams.Credential = $Credential
            }

            $queryResult = Invoke-AssessmentADRemoteCimQuery @transportParams
        }
        catch {

            $queryResult = [PSCustomObject][ordered]@{
                ComputerName     = $ComputerName
                Transport        = 'None'
                Status           = 'NotAvailable'
                DataAvailability = 'NotAvailable'
                Data             = @()
                ErrorType        = 'RemoteQueryError'
                ErrorMessage     = $_.Exception.Message
                IsReadOnly       = $true
            }
        }

        # ------------------------------------------------------------
        # Transport failure
        # ------------------------------------------------------------

        if (
            $null -eq $queryResult -or
            $queryResult.Status -ne 'Available'
        ) {

            [PSCustomObject][ordered]@{

                ComputerName     = $ComputerName
                GroupName        = $null
                GroupMembers     = @()
                CollectionMethod = 'WMI'
                Transport        = if ($null -ne $queryResult) {
                    $queryResult.Transport
                }
                else {
                    'None'
                }
                Status           = 'NotAvailable'
                DataAvailability = 'NotAvailable'
                ErrorType        = if ($null -ne $queryResult) {
                    $queryResult.ErrorType
                }
                else {
                    'RemoteQueryError'
                }
                ErrorMessage     = if ($null -ne $queryResult) {
                    $queryResult.ErrorMessage
                }
                else {
                    'Remote query failed.'
                }
                IsReadOnly       = $true
            }

            return
        }

        # ------------------------------------------------------------
        # Normalize results
        # ------------------------------------------------------------

        foreach ($item in @($queryResult.Data)) {

            if ($null -eq $item) {
                continue
            }

            $members = @()

            if (
                $item.PSObject.Properties['GroupMembers'] -and
                $null -ne $item.GroupMembers
            ) {
                $members = @($item.GroupMembers)
            }

            $memberStatus = 'Available'

            if (
                $item.PSObject.Properties['MemberStatus'] -and
                $item.MemberStatus
            ) {
                $memberStatus = [string]$item.MemberStatus
            }

            [PSCustomObject][ordered]@{

                # IMPORTANT:
                # Always use the requested target, not the local
                # PowerShell session computer name.

                ComputerName = $ComputerName

                GroupName = [string]$item.GroupName

                GroupMembers = $members

                CollectionMethod = 'WMI'

                Transport = [string]$queryResult.Transport

                Status = if ($memberStatus -eq 'Partial') {
                    'Partial'
                }
                else {
                    'Available'
                }

                DataAvailability = 'Available'

                ErrorType = $null

                ErrorMessage = $null

                IsReadOnly = $true
            }
        }
    }
}