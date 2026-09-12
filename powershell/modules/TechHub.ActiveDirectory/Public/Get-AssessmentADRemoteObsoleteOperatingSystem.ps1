#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteObsoleteOperatingSystem {
    <#
    .SYNOPSIS
        Flags remote Windows computers running an obsolete (end-of-support)
        operating system, returning one security finding per computer.

    .DESCRIPTION
        Read-only remote assessment. Wraps Get-AssessmentADRemoteOSInfo and
        classifies the reported OSCaption against a configurable list of
        end-of-support patterns.

        When -ComputerName is not supplied, targets are discovered with
        Get-AssessmentADRemoteTargets (default -TargetType All).

    .PARAMETER ComputerName
        Explicit list of computers to assess. Bypasses automatic discovery.

    .PARAMETER TargetType
        Discovery scope used when -ComputerName is not supplied. Defaults
        to 'All'.

    .PARAMETER ObsoleteOSPatterns
        Wildcard patterns matched against OSCaption. Defaults to a list of
        Windows versions that are past mainstream end-of-support.

    .PARAMETER Credential
        Optional alternate credential for the remote CIM connection.

    .PARAMETER UseSSL
        Requests the WSMan transport over HTTPS.

    .PARAMETER Server
        Domain controller used to build a provider for target discovery,
        when -Provider is not supplied.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider, used for target discovery.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$TargetType = 'All',

        [Parameter()]
        [string[]]$ObsoleteOSPatterns = @(
            '*Windows XP*'
            '*Windows Vista*'
            '*Windows 7*'
            '*Windows 8*'
            '*Windows Server 2003*'
            '*Windows Server 2008*'
            '*Windows Server 2012*'
        ),

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$UseSSL,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-OBSOLETE-OS'
    $CheckName = 'Obsolete Operating System'

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('ComputerName')) {

        $Targets = @(
            $ComputerName |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    else {

        if ($null -eq $Provider) {
            $Provider = New-AssessmentADProvider -Server $Server
        }

        try {
            Write-Verbose -Message ('Discovering remote targets (TargetType = {0}).' -f $TargetType)

            $Targets = @(
                Get-AssessmentADRemoteTargets -Provider $Provider -TargetType $TargetType |
                    ForEach-Object { [string]$_.ComputerName } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        catch {
            Write-Error -ErrorRecord $_
            return
        }
    }

    if ($Targets.Count -eq 0) {
        Write-Verbose -Message 'No targets were supplied or discovered; nothing to assess.'
        return
    }

    foreach ($Target in $Targets) {

        Write-Verbose -Message "[$Target] Collecting operating system information."

        $OsInfoParams = @{
            ComputerName = $Target
            UseSSL       = $UseSSL
        }

        if ($PSBoundParameters.ContainsKey('Credential')) {
            $OsInfoParams.Credential = $Credential
        }

        $OsInfo = @(Get-AssessmentADRemoteOSInfo @OsInfoParams) | Select-Object -First 1

        if ($null -eq $OsInfo -or $OsInfo.Status -ne 'Available') {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('Obsolete OS assessment unavailable for {0}' -f $Target) `
                -Description 'The operating system of this computer could not be determined.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence (
                    [PSCustomObject][ordered]@{
                        ErrorType    = $(if ($null -ne $OsInfo) { $OsInfo.ErrorType } else { 'NoData' })
                        ErrorMessage = $(if ($null -ne $OsInfo) { $OsInfo.ErrorMessage } else { 'No OS information was returned.' })
                    }
                ) `
                -Risk 'No security conclusion can be made because the operating system could not be determined.' `
                -Recommendation 'Verify remote management connectivity to the target and rerun the assessment.' `
                -References @('https://learn.microsoft.com/lifecycle/products/') `
                -Domain $null `
                -Forest $null `
                -DomainController $null

            continue
        }

        $MatchedPattern = $null

        foreach ($Pattern in $ObsoleteOSPatterns) {
            if ([string]$OsInfo.OSCaption -like $Pattern) {
                $MatchedPattern = $Pattern
                break
            }
        }

        $IsObsolete = ($null -ne $MatchedPattern)

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Hardening' `
            -Title ('Operating system: {0}' -f $Target) `
            -Description $(if ($IsObsolete) { 'This computer runs an operating system past its mainstream end-of-support date.' } else { 'This computer does not match any configured obsolete OS pattern.' }) `
            -Severity $(if ($IsObsolete) { 'High' } else { 'Informational' }) `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
            -ObjectType 'Computer' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    OSCaption      = $OsInfo.OSCaption
                    OSVersion      = $OsInfo.OSVersion
                    OSBuildNumber  = $OsInfo.OSBuildNumber
                    TargetType     = $OsInfo.TargetType
                    MatchedPattern = $MatchedPattern
                    IsObsolete     = $IsObsolete
                }
            ) `
            -Risk 'An unsupported operating system no longer receives security updates, leaving known vulnerabilities permanently unpatched.' `
            -Recommendation 'Upgrade or decommission this computer. If it must remain in service, isolate it on the network and compensate with additional monitoring and access controls.' `
            -References @('https://learn.microsoft.com/lifecycle/products/') `
            -Domain $null `
            -Forest $null `
            -DomainController $null
    }
}
