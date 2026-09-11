function Invoke-AssessmentADFullAssessment {
    <#
    .SYNOPSIS
        Runs the complete Active Directory security assessment plus the
        remote infrastructure assessment, and exports one HTML report.

    .DESCRIPTION
        Convenience orchestrator for a full, "one command" assessment:

        1. Runs Invoke-AssessmentADAssessment (all enabled registry checks).
        2. Unless -SkipRemoteAssessment is used, discovers remote targets
           (or uses the supplied -ComputerName list) and runs
           Invoke-AssessmentADRemoteAssessment against each, merging the
           results into the same assessment.
        3. Exports the combined assessment to a single HTML report.

        This function only composes the existing, independently testable
        building blocks; it does not add new collection or scoring logic.

    .PARAMETER Server
        Domain controller to target. Optional; omit for normal AD site/DC
        auto-discovery.

    .PARAMETER TargetType
        Remote target discovery scope passed to Get-AssessmentADRemoteTargets
        when -ComputerName is not supplied. Defaults to 'Server'.

    .PARAMETER ComputerName
        Explicit list of computers for the remote assessment, bypassing
        automatic discovery.

    .PARAMETER SkipRemoteAssessment
        Runs only the Active Directory security assessment; no remote
        computer is contacted.

    .PARAMETER OutputPath
        Path for the HTML report. Defaults to a timestamped file
        (AD-Assessment-yyyyMMdd-HHmmss.html) in the current directory.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider. A new one is created from
        -Server when omitted.

    .OUTPUTS
        A [PSCustomObject] with:
            Assessment  the combined TechHubADAssessmentResult
            ReportPath  the path the HTML report was written to

    .EXAMPLE
        Invoke-AssessmentADFullAssessment -Server dc01.example.test

    .EXAMPLE
        Invoke-AssessmentADFullAssessment -Server dc01.example.test -ComputerName 'srv01','srv02' -OutputPath .\report.html
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$TargetType = 'Server',

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [switch]$SkipRemoteAssessment,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [object]$Provider
    )

    if ($null -eq $Provider) {
        $Provider = New-AssessmentADProvider -Server $Server
    }

    Write-Verbose -Message 'Running the Active Directory security assessment.'

    $Assessment = Invoke-AssessmentADAssessment -Server $Server -Provider $Provider

    if (-not $SkipRemoteAssessment) {

        $Targets = @()

        if ($PSBoundParameters.ContainsKey('ComputerName')) {

            $Targets = @(
                $ComputerName |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } }
            )
        }
        else {

            Write-Verbose -Message (
                'Discovering remote targets (TargetType = {0}).' -f $TargetType
            )

            $Targets = @(
                Get-AssessmentADRemoteTargets -Provider $Provider -TargetType $TargetType
            )
        }

        foreach ($Target in $Targets) {

            $TargetComputerName = $null

            if ($null -ne $Target.PSObject.Properties['ComputerName']) {
                $TargetComputerName = [string]$Target.PSObject.Properties['ComputerName'].Value
            }

            if ([string]::IsNullOrWhiteSpace($TargetComputerName)) {
                continue
            }

            Write-Verbose -Message (
                'Collecting remote infrastructure data from {0}.' -f $TargetComputerName
            )

            $Assessment = Invoke-AssessmentADRemoteAssessment `
                -ComputerName $TargetComputerName `
                -Assessment $Assessment
        }
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {

        $OutputPath = Join-Path `
            -Path (Get-Location).Path `
            -ChildPath ('AD-Assessment-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    Write-Verbose -Message ('Exporting HTML report to {0}.' -f $OutputPath)

    Export-AssessmentADAssessmentHtml -Assessment $Assessment -Path $OutputPath

    [PSCustomObject][ordered]@{
        Assessment = $Assessment
        ReportPath = $OutputPath
    }
}
