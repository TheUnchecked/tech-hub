#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADRemoteLocalGroups {
    <#
    .SYNOPSIS
        Collects local group membership from selected Active Directory computer targets.

    .DESCRIPTION
        Uses Get-AssessmentADRemoteTargets for target discovery and
        Get-AssessmentADRemoteLocalGroups for remote collection and
        classification. This function is read-only.

    .PARAMETER TargetType
        Target selection mode: All, Server, Client, DomainController.

    .PARAMETER SearchBase
        Optional Active Directory OU/container Distinguished Name.

    .PARAMETER IncludeDisabled
        Includes disabled computer accounts.

    .PARAMETER ComputerName
        Optional explicit computer names. When specified, AD target
        discovery is bypassed.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        See Get-AssessmentADRemoteLocalGroups.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('All', 'Server', 'Client', 'DomainController')]
        [string]$TargetType = 'All',

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Starting remote local group assessment. TargetType=$TargetType"

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('ComputerName') -and $ComputerName.Count -gt 0) {

        Write-Verbose 'Explicit computer names supplied. AD target discovery will be bypassed.'
        $Targets = @($ComputerName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    else {

        $TargetParameters = @{
            TargetType  = $TargetType
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $TargetParameters.SearchBase = $SearchBase }
        if ($IncludeDisabled) { $TargetParameters.IncludeDisabled = $true }

        $Targets = @(Get-AssessmentADRemoteTargets @TargetParameters | Select-Object -ExpandProperty ComputerName)
    }

    if ($Targets.Count -eq 0) {
        Write-Verbose 'No remote assessment targets were discovered.'
        return
    }

    Write-Verbose "Remote targets selected: $($Targets.Count)"

    $CollectorParameters = @{ ErrorAction = 'Continue' }

    if ($null -ne $Credential) { $CollectorParameters.Credential = $Credential }

    $Targets | Get-AssessmentADRemoteLocalGroups @CollectorParameters
}
