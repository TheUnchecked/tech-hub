#requires -Version 5.1

Set-StrictMode -Version Latest

function New-AssessmentADProviderReadResponse {

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

function Get-AssessmentADProviderDomainInformation {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADDomain @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderForestInformation {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADForest @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderDomainControllers {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Filter = '*'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADDomainController @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderObjects {

    [CmdletBinding()]
    param(
        [string]$LDAPFilter,
        [string]$SearchBase,
        [string[]]$Properties,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
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
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data $Objects
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderGroups {

    [CmdletBinding()]
    param(
        [string]$Filter,
        [string]$SearchBase,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
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

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADGroup @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderDefaultPasswordPolicy {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADDefaultDomainPasswordPolicy @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderFineGrainedPasswordPolicies {

    [CmdletBinding()]
    param(
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Filter = '*'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADFineGrainedPasswordPolicy @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderObjectSecurityDescriptor {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{
            Identity    = $Identity
            Properties  = @('nTSecurityDescriptor')
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        $Object = Get-ADObject @Parameters

        $SecurityDescriptor = $null
        if ($null -ne $Object -and $null -ne $Object.PSObject.Properties['nTSecurityDescriptor']) {
            $SecurityDescriptor = $Object.PSObject.Properties['nTSecurityDescriptor'].Value
        }

        $Aces = @()
        if ($null -ne $SecurityDescriptor -and $null -ne $SecurityDescriptor.Access) {
            $Aces = @(
                $SecurityDescriptor.Access |
                    ForEach-Object {
                        ConvertTo-TechHubADProviderAce -InputObject $_
                    }
            )
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data $Aces
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderOptionalFeatures {

    [CmdletBinding()]
    param(
        [string]$Filter = '*',
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Filter = $Filter; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADOptionalFeature @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}

function Get-AssessmentADProviderGroupMembers {

    [CmdletBinding()]
    param(
        [string]$Identity,
        [string]$Server
    )

    if (-not (Test-TechHubADProviderReadAvailability)) {
        return New-AssessmentADProviderReadResponse -IsAvailable $false
    }

    try {
        $Parameters = @{ Identity = $Identity; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $Parameters.Server = $Server
        }

        return New-AssessmentADProviderReadResponse -IsAvailable $true -Data @(Get-ADGroupMember @Parameters)
    }
    catch {
        return New-AssessmentADProviderReadResponse -IsAvailable $true -Exception $_.Exception
    }
}
