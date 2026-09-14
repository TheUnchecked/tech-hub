#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADAssessment {
    <#
    .SYNOPSIS
        Runs the Active Directory security checks and returns their combined results.

    .DESCRIPTION
        Calls Get-AssessmentADUnconstrainedDelegation, Get-AssessmentADConstrainedDelegation,
        Get-AssessmentADRBCD and Get-AssessmentADPrivilegedGroup in sequence and returns one
        flat array, each record tagged with the CheckId that produced it. Reports facts only;
        it does not compute a risk severity - that judgment is left to the reader.

    .PARAMETER CheckId
        Restrict execution to one or more of: AD-UNCONSTRAINED-DELEGATION,
        AD-CONSTRAINED-DELEGATION, AD-RBCD, AD-PRIVILEGED-GROUP. Runs all
        four by default.

    .PARAMETER Server
        Optional domain controller, forwarded to every check.

    .PARAMETER SearchBase
        Optional Distinguished Name, forwarded to every check.

    .OUTPUTS
        The combined objects from each check, each with an added CheckId property.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('AD-UNCONSTRAINED-DELEGATION', 'AD-CONSTRAINED-DELEGATION', 'AD-RBCD', 'AD-PRIVILEGED-GROUP')]
        [string[]]$CheckId,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    $CommonParameters = @{}

    if (-not [string]::IsNullOrWhiteSpace($Server)) { $CommonParameters.Server = $Server }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $CommonParameters.SearchBase = $SearchBase }

    $Checks = [ordered]@{
        'AD-UNCONSTRAINED-DELEGATION' = 'Get-AssessmentADUnconstrainedDelegation'
        'AD-CONSTRAINED-DELEGATION'   = 'Get-AssessmentADConstrainedDelegation'
        'AD-RBCD'                     = 'Get-AssessmentADRBCD'
        'AD-PRIVILEGED-GROUP'         = 'Get-AssessmentADPrivilegedGroup'
    }

    $SelectedCheckIds = if ($PSBoundParameters.ContainsKey('CheckId')) { $CheckId } else { @($Checks.Keys) }

    foreach ($SelectedCheckId in $SelectedCheckIds) {

        $FunctionName = $Checks[$SelectedCheckId]

        Write-Verbose "Running $SelectedCheckId ($FunctionName)."

        try {
            $Results = @(& $FunctionName @CommonParameters -ErrorAction Stop)
        }
        catch {
            Write-Error -Message "$SelectedCheckId failed: $($_.Exception.Message)"
            continue
        }

        foreach ($Result in $Results) {

            if ($null -eq $Result) { continue }

            $Result | Add-Member -NotePropertyName CheckId -NotePropertyValue $SelectedCheckId -PassThru -Force
        }
    }
}
