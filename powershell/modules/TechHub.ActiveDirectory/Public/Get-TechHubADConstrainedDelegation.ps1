function Get-TechHubADConstrainedDelegation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$CriticalServicePatterns = @(),

        [Parameter()]
        [string[]]$DocumentedServicePatterns = @(),

        [Parameter()]
        [string[]]$ExcludedServicePatterns = @()
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-CONSTRAINED-DELEGATION'
    $CheckName = 'Constrained Delegation'
    $AccountDisabled = [int64]0x2
    $Properties = @(
        'DistinguishedName'
        'Name'
        'ObjectGUID'
        'ObjectClass'
        'ObjectCategory'
        'SamAccountName'
        'UserAccountControl'
        'Enabled'
        'ServicePrincipalName'
        'msDS-AllowedToDelegateTo'
    )
    $QueryParameters = @{
        LDAPFilter  = '(&(msDS-AllowedToDelegateTo=*)(|(objectCategory=computer)(objectCategory=person)))'
        Properties  = $Properties
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $QueryParameters.Server = $Server
    }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $QueryParameters.SearchBase = $SearchBase
    }

    $Domain = $null
    $Forest = $null
    $DomainController = $Server

    try {
        $DomainParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $DomainParameters.Server = $Server
        }
        $DomainContext = Get-ADDomain @DomainParameters
        if ($null -ne $DomainContext) {
            $Domain = $DomainContext.DNSRoot
        }
    }
    catch {
        Write-Verbose -Message ('Unable to collect domain context: {0}' -f $_.Exception.Message)
    }

    try {
        $ForestParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $ForestParameters.Server = $Server
        }
        $ForestContext = Get-ADForest @ForestParameters
        if ($null -ne $ForestContext) {
            $Forest = $ForestContext.Name
        }
    }
    catch {
        Write-Verbose -Message ('Unable to collect forest context: {0}' -f $_.Exception.Message)
    }

    try {
        Write-Verbose -Message 'Querying Active Directory for constrained delegation.'
        $Objects = @(Get-ADObject @QueryParameters)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    Write-Verbose -Message ('Found {0} object(s) with msDS-AllowedToDelegateTo.' -f $Objects.Count)

    foreach ($Object in $Objects) {
        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = $null
        $ObjectClassValues = @()
        $ObjectCategoryValues = @()
        $ServicePrincipalNames = @()
        $AllowedToDelegateTo = @()
        $UserAccountControl = $null
        $HasCompleteUac = $false

        if ($null -ne $Object.PSObject.Properties['Name']) {
            $Name = [string]$Object.PSObject.Properties['Name'].Value
        }
        if ($null -ne $Object.PSObject.Properties['DistinguishedName']) {
            $DistinguishedName = [string]$Object.PSObject.Properties['DistinguishedName'].Value
        }
        if ($null -ne $Object.PSObject.Properties['SamAccountName']) {
            $SamAccountName = [string]$Object.PSObject.Properties['SamAccountName'].Value
        }
        if ($null -ne $Object.PSObject.Properties['ObjectGUID']) {
            try {
                $ObjectGuid = [guid]$Object.PSObject.Properties['ObjectGUID'].Value
            }
            catch {
                Write-Verbose -Message 'An object has an invalid ObjectGUID value.'
            }
        }
        if ($null -ne $Object.PSObject.Properties['ObjectClass']) {
            $ObjectClassValues = @($Object.PSObject.Properties['ObjectClass'].Value)
        }
        if ($null -ne $Object.PSObject.Properties['ObjectCategory']) {
            $ObjectCategoryValues = @($Object.PSObject.Properties['ObjectCategory'].Value)
        }
        if ($null -ne $Object.PSObject.Properties['ServicePrincipalName']) {
            $ServicePrincipalNames = @($Object.PSObject.Properties['ServicePrincipalName'].Value |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        if ($null -ne $Object.PSObject.Properties['msDS-AllowedToDelegateTo']) {
            $AllowedToDelegateTo = @($Object.PSObject.Properties['msDS-AllowedToDelegateTo'].Value |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        try {
            if ($null -eq $Object.PSObject.Properties['UserAccountControl']) {
                throw 'UserAccountControl property is missing.'
            }
            $UserAccountControl = [int64]$Object.PSObject.Properties['UserAccountControl'].Value
            $HasCompleteUac = $true
        }
        catch {
            Write-Verbose -Message 'An object has an invalid or missing UserAccountControl value.'
        }

        if ($AllowedToDelegateTo.Count -eq 0) {
            Write-Verbose -Message ('Skipping object {0} because no delegation destination was returned.' -f $Name)
            continue
        }

        $ObjectType = 'Unknown'
        if ($ObjectClassValues -contains 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectClassValues -contains 'user') {
            $ObjectType = 'User'
        }
        elseif ($ObjectCategoryValues -match 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectCategoryValues -match 'person') {
            $ObjectType = 'User'
        }

        $Enabled = $null
        if ($null -ne $Object.PSObject.Properties['Enabled'] -and
            $null -ne $Object.PSObject.Properties['Enabled'].Value) {
            $Enabled = [bool]$Object.PSObject.Properties['Enabled'].Value
        }
        elseif ($HasCompleteUac) {
            $Enabled = (($UserAccountControl -band $AccountDisabled) -eq 0)
        }

        $CriticalMatches = @()
        if ($CriticalServicePatterns.Count -gt 0) {
            $CriticalMatches = @($AllowedToDelegateTo | Where-Object {
                $Destination = $_
                @($CriticalServicePatterns | Where-Object { $Destination -like $_ }).Count -gt 0
            })
        }
        $DocumentedMatches = @()
        if ($DocumentedServicePatterns.Count -gt 0) {
            $DocumentedMatches = @($AllowedToDelegateTo | Where-Object {
                $Destination = $_
                @($DocumentedServicePatterns | Where-Object { $Destination -like $_ }).Count -gt 0
            })
        }
        $ExcludedMatches = @()
        if ($ExcludedServicePatterns.Count -gt 0) {
            $ExcludedMatches = @($AllowedToDelegateTo | Where-Object {
                $Destination = $_
                @($ExcludedServicePatterns | Where-Object { $Destination -like $_ }).Count -gt 0
            })
        }

        $Severity = 'Low'
        $Status = 'Finding'
        if ($Enabled -eq $false) {
            $Severity = 'Informational'
        }
        elseif ($CriticalMatches.Count -gt 0) {
            $Severity = 'High'
        }
        elseif ($AllowedToDelegateTo.Count -gt 1 -or
            ($DocumentedServicePatterns.Count -gt 0 -and $DocumentedMatches.Count -ne $AllowedToDelegateTo.Count)) {
            $Severity = 'Medium'
        }
        if ($ExcludedMatches.Count -eq $AllowedToDelegateTo.Count -and $ExcludedMatches.Count -gt 0) {
            $Severity = 'Informational'
            $Status = 'NotApplicable'
        }

        $Confidence = 'High'
        if (-not $HasCompleteUac -or [string]::IsNullOrWhiteSpace($DistinguishedName) -or
            [string]::IsNullOrWhiteSpace($Name)) {
            $Confidence = 'Medium'
        }

        $AffectedObject = [PSCustomObject][ordered]@{
            Name        = $Name
            ObjectClass = $ObjectType
            Enabled     = $Enabled
        }
        $Evidence = [PSCustomObject][ordered]@{
            AllowedToDelegateTo    = $AllowedToDelegateTo
            ServicePrincipalNames  = $ServicePrincipalNames
            AccountEnabled         = $Enabled
            UserAccountControl     = $UserAccountControl
            CriticalMatches        = $CriticalMatches
            DocumentedMatches      = $DocumentedMatches
            ExcludedMatches        = $ExcludedMatches
        }

        $Risk = 'The delegation configuration should be reviewed because a compromised delegating account could affect authentication to the listed services.'
        if ($Enabled -eq $false) {
            $Risk = 'The account is disabled, but the delegation configuration should be reviewed before the account is enabled.'
        }
        elseif ($CriticalMatches.Count -gt 0) {
            $Risk = 'The delegation targets a service matched by the supplied sensitive-service patterns and requires priority review.'
        }

        New-TechHubADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Title ('Constrained delegation on {0}' -f $Name) `
            -Description 'The account is configured with one or more constrained delegation service principals.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status $Status `
            -AffectedObject $AffectedObject `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk $Risk `
            -Recommendation 'Review the business requirement, minimize delegation destinations, remove stale SPNs, and document approved exceptions.' `
            -References @('https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
