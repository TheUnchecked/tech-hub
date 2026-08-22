function Get-TechHubADUnconstrainedDelegation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-UNCONSTRAINED-DELEGATION'
    $CheckName = 'Unconstrained Delegation'
    $TrustedForDelegation = [int64]0x80000
    $AccountDisabled = [int64]0x2
    $Properties = @(
        'DistinguishedName'
        'Name'
        'ObjectGUID'
        'ObjectClass'
        'ObjectCategory'
        'SamAccountName'
        'UserAccountControl'
        'ServicePrincipalName'
    )

    $QueryParameters = @{
        LDAPFilter  = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(|(objectCategory=computer)(objectCategory=person)))'
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
        Write-Verbose -Message 'Querying Active Directory for unconstrained delegation.'
        $Objects = @(Get-ADObject @QueryParameters)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    Write-Verbose -Message ('Found {0} object(s) with TRUSTED_FOR_DELEGATION.' -f $Objects.Count)

    foreach ($Object in $Objects) {
        $UserAccountControl = $null
        $HasCompleteUac = $false
        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = $null
        $ObjectClassValues = @()
        $ObjectCategoryValues = @()
        $ServicePrincipalNames = @()

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

        try {
            if ($null -eq $Object.PSObject.Properties['userAccountControl']) {
                throw 'userAccountControl property is missing.'
            }

            $UserAccountControl = [int64]$Object.PSObject.Properties['userAccountControl'].Value
            $HasCompleteUac = $true
        }
        catch {
            Write-Verbose -Message 'An object has an invalid or missing userAccountControl value.'
        }

        if ($HasCompleteUac -and (($UserAccountControl -band $TrustedForDelegation) -eq 0)) {
            continue
        }

        $ObjectType = 'Unknown'
        if ($ObjectClassValues -contains 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectClassValues -contains 'user') {
            $ObjectType = 'User'
        }
        else {
            if ($ObjectCategoryValues -match 'computer') {
                $ObjectType = 'Computer'
            }
            elseif ($ObjectCategoryValues -match 'person') {
                $ObjectType = 'User'
            }
        }

        $Enabled = $true
        if ($HasCompleteUac) {
            $Enabled = (($UserAccountControl -band $AccountDisabled) -eq 0)
        }
        else {
            $Enabled = $null
        }

        $Severity = 'High'
        if ($Enabled -eq $false) {
            $Severity = 'Medium'
        }

        $Confidence = 'High'
        if (-not $HasCompleteUac -or [string]::IsNullOrWhiteSpace($DistinguishedName)) {
            $Confidence = 'Medium'
        }

        $AffectedObject = [PSCustomObject][ordered]@{
            Name          = $Name
            ObjectClass   = $ObjectType
            Enabled       = $Enabled
        }
        $Evidence = [PSCustomObject][ordered]@{
            UserAccountControl       = $UserAccountControl
            TrustedForDelegation     = (($HasCompleteUac) -and (($UserAccountControl -band $TrustedForDelegation) -ne 0))
            AccountEnabled           = $Enabled
            ServicePrincipalNames    = $ServicePrincipalNames
        }

        $Description = 'The account is configured for unconstrained Kerberos delegation.'
        $Risk = 'If this enabled account is compromised, Kerberos authentications to the account can increase the impact of the compromise.'
        if ($Enabled -eq $false) {
            $Risk = 'The account is disabled, but the delegation configuration should be reviewed before the account is enabled.'
        }

        New-TechHubADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Title ('Unconstrained delegation on {0}' -f $Name) `
            -Description $Description `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status 'Finding' `
            -AffectedObject $AffectedObject `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk $Risk `
            -Recommendation 'Review the business requirement, remove unconstrained delegation when it is not required, and prefer a narrowly scoped delegation model.' `
            -References @('https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
