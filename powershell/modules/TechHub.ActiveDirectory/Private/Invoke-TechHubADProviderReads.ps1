#requires -Version 5.1

Set-StrictMode -Version Latest

function New-TechHubADProviderReadResponse {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$IsAvailable,

        [object[]]$Data = @(),

        [System.Exception]$Exception
    )

    [PSCustomObject]@{
        IsAvailable = $IsAvailable
        Data        = @($Data)
        Exception   = $Exception
    }
}

function Test-TechHubADProviderReadAvailability {

    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Test-TechHubADActiveDirectoryAvailability
}

function Get-TechHubADProviderDomainInformation {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-TechHubADProviderReadResponse -IsAvailable $true -Data @(Get-ADDomain @Parameters)
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-TechHubADProviderForestInformation {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-TechHubADProviderReadResponse -IsAvailable $true -Data @(Get-ADForest @Parameters)
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-TechHubADProviderDomainControllers {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Filter = '*'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-TechHubADProviderReadResponse -IsAvailable $true -Data @(Get-ADDomainController @Parameters)
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-TechHubADProviderObjects {

    [CmdletBinding()]
    param(
        [string]$LDAPFilter,
        [string]$SearchBase,
        [string[]]$Properties,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{
            LDAPFilter  = $LDAPFilter
            Properties  = $Properties
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $Parameters.SearchBase = $SearchBase
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        $Objects = @(Get-ADObject @Parameters | ForEach-Object {
            ConvertTo-TechHubADProviderObject -InputObject $_
        })
        return New-TechHubADProviderReadResponse -IsAvailable $true -Data $Objects
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-TechHubADProviderGroups {

    [CmdletBinding()]
    param(
        [string]$Filter,
        [string]$SearchBase,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Filter = '*'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Filter)) {
            $Parameters.Filter = $Filter
        }
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $Parameters.SearchBase = $SearchBase
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-TechHubADProviderReadResponse -IsAvailable $true -Data @(Get-ADGroup @Parameters)
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-TechHubADProviderGroupMembers {

    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-TechHubADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Identity = $Identity; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-TechHubADProviderReadResponse -IsAvailable $true -Data @(Get-ADGroupMember @Parameters)
    }
    catch {
        return New-TechHubADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}
