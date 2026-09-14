#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteLocalGroups {
    <#
    .SYNOPSIS
        Lists local group membership on remote computers, one record per member.

    .DESCRIPTION
        Wraps Get-AssessmentADRemoteLocalGroupMembers and flattens the
        result to one record per member, classifying each member as
        LocalAccount, DomainPrincipal, BuiltInPrincipal, WellKnownPrincipal
        or Unknown. Reports facts only; it does not compute a risk
        severity.

    .PARAMETER ComputerName
        One or more remote computers. Supports pipeline input.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName, TargetType, GroupName, Member, Domain, Name, SID,
        LocalAccount, AccountType, MemberType, CollectionMethod,
        Transport, Status, DataAvailability, ErrorType, ErrorMessage,
        IsReadOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Computer', 'CN', 'Host', 'Name', 'DNSHostName')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        foreach ($Computer in $ComputerName) {

            Write-Verbose "Collecting local groups on [$Computer]."

            $CollectorParameters = @{
                ComputerName = $Computer
                ErrorAction  = 'Stop'
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $CollectorParameters.Credential = $Credential
            }

            try {
                $Groups = @(Get-AssessmentADRemoteLocalGroupMembers @CollectorParameters)
            }
            catch {
                Write-Error -Message "[$Computer] Remote query failed: $($_.Exception.Message)"
                continue
            }

            foreach ($GroupResult in $Groups) {

                if ($null -eq $GroupResult) { continue }

                ConvertTo-AssessmentADRemoteLocalGroupMember -InputObject $GroupResult
            }
        }
    }
}
