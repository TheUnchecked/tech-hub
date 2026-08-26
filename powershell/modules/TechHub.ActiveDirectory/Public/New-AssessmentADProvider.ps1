function New-AssessmentADProvider {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server
    )

    [TechHubADProvider]::new($Server)
}
