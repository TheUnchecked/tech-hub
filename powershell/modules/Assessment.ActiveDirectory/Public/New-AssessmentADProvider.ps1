function New-AssessmentADProvider {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server
    )

    [AssessmentADProvider]::new($Server)
}
