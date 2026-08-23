function New-TechHubADProvider {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server
    )

    [TechHubADProvider]::new($Server)
}
