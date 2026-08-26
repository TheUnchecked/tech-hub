function Get-AssessmentADConstrainedDelegation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Forest,

        [Parameter()]
        [string]$DomainController,

        [Parameter()]
        [string[]]$CriticalServicePatterns = @(),

        [Parameter()]
        [string[]]$DocumentedServicePatterns = @(),

        [Parameter()]
        [string[]]$ExcludedServicePatterns = @(),

        [Parameter()]
        [object]$Provider
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

    $LdapFilter = '(&(msDS-AllowedToDelegateTo=*)(|(objectCategory=computer)(objectCategory=person)))'

    if ($null -eq $Provider) {
        $Provider = New-AssessmentADProvider -Server $Server
    }

    $DomainResult = $null
    $ForestResult = $null

    try {
        $DomainResult = $Provider.GetDomainInformation()
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect domain context from provider: {0}' -f
            $_.Exception.Message
        )
    }

    try {
        $ForestResult = $Provider.GetForestInformation()
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect forest context from provider: {0}' -f
            $_.Exception.Message
        )
    }

    if (
        [string]::IsNullOrWhiteSpace($Domain) -and
        $null -ne $DomainResult -and
        $DomainResult.Status -eq 'Available' -and
        @($DomainResult.Data).Count -gt 0
    ) {
        $DomainData = @($DomainResult.Data)[0]

        if ($null -ne $DomainData.PSObject.Properties['DNSRoot']) {
            $Domain = [string]$DomainData.PSObject.Properties['DNSRoot'].Value
        }
    }

    if (
        [string]::IsNullOrWhiteSpace($Forest) -and
        $null -ne $ForestResult -and
        $ForestResult.Status -eq 'Available' -and
        @($ForestResult.Data).Count -gt 0
    ) {
        $ForestData = @($ForestResult.Data)[0]

        if ($null -ne $ForestData.PSObject.Properties['Name']) {
            $Forest = [string]$ForestData.PSObject.Properties['Name'].Value
        }
    }

    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        $DomainController = $Server
    }

    try {
        Write-Verbose -Message `
            'Requesting constrained delegation objects from TechHubADProvider.'

        $ObjectsResult = $Provider.GetADObjects(
            $LdapFilter,
            $SearchBase,
            $Properties
        )
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $ObjectsResult) {
        Write-Error `
            -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $ProviderStatus = [string]$ObjectsResult.Status
    $Objects = @($ObjectsResult.Data)

    if (
        $ProviderStatus -eq 'NotAvailable' -or
        $ProviderStatus -eq 'Error'
    ) {
        Write-Verbose -Message (
            'Provider could not retrieve required objects: {0}' -f
            $ObjectsResult.ErrorMessage
        )

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Title 'Constrained delegation assessment unavailable' `
            -Description 'The provider could not retrieve the Active Directory data required for this check.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $ProviderStatus `
            -AffectedObject (
                [PSCustomObject][ordered]@{
                    Name        = $null
                    ObjectClass = 'Unknown'
                    Enabled     = $null
                }
            ) `
            -ObjectType 'Unknown' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    ProviderStatus       = $ProviderStatus
                    ErrorType             = $ObjectsResult.ErrorType
                    ErrorMessage          = $ObjectsResult.ErrorMessage
                    AllowedToDelegateTo   = @()
                    AccountEnabled        = $null
                    ServicePrincipalNames = @()
                    UserAccountControl    = $null
                }
            ) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @(
                'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    Write-Verbose -Message (
        'Provider returned {0} object(s) with msDS-AllowedToDelegateTo.' -f
        $Objects.Count
    )

    foreach ($Object in $Objects) {

        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = [guid]::Empty
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
            $RawObjectGuid = $Object.PSObject.Properties['ObjectGUID'].Value

            if ($null -ne $RawObjectGuid) {
                try {
                    $ObjectGuid = [guid]$RawObjectGuid
                }
                catch {
                    $ObjectGuid = [guid]::Empty

                    Write-Verbose `
                        -Message 'Provider returned an invalid ObjectGUID.'
                }
            }
        }

        if ($null -ne $Object.PSObject.Properties['ObjectClass']) {
            $ObjectClassValues = @(
                $Object.PSObject.Properties['ObjectClass'].Value
            )
        }

        if ($null -ne $Object.PSObject.Properties['ObjectCategory']) {
            $ObjectCategoryValues = @(
                $Object.PSObject.Properties['ObjectCategory'].Value
            )
        }

        if ($null -ne $Object.PSObject.Properties['ServicePrincipalName']) {
            $ServicePrincipalNames = @(
                $Object.PSObject.Properties['ServicePrincipalName'].Value |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        }

        if ($null -ne $Object.PSObject.Properties['msDS-AllowedToDelegateTo']) {
            $AllowedToDelegateTo = @(
                $Object.PSObject.Properties['msDS-AllowedToDelegateTo'].Value |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        }

        if ($null -ne $Object.PSObject.Properties['UserAccountControl']) {
            try {
                $UserAccountControl = [int64]$Object.PSObject.Properties['UserAccountControl'].Value
                $HasCompleteUac = $true
            }
            catch {
                Write-Verbose `
                    -Message 'Provider returned an invalid UserAccountControl.'
            }
        }

        if ($AllowedToDelegateTo.Count -eq 0) {
            Write-Verbose -Message (
                'Skipping object {0} because no delegation destination was returned.' -f
                $Name
            )
            continue
        }

        $ObjectType = 'Unknown'

        if ($ObjectClassValues -contains 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectClassValues -contains 'user') {
            $ObjectType = 'User'
        }
        elseif ($ObjectCategoryValues -contains 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectCategoryValues -contains 'person') {
            $ObjectType = 'User'
        }

        $Enabled = $null

        if (
            $null -ne $Object.PSObject.Properties['Enabled'] -and
            $null -ne $Object.PSObject.Properties['Enabled'].Value
        ) {
            $Enabled = [bool]$Object.PSObject.Properties['Enabled'].Value
        }
        elseif ($HasCompleteUac) {
            $Enabled = (($UserAccountControl -band $AccountDisabled) -eq 0)
        }

        $CriticalMatches = @(
            $AllowedToDelegateTo |
                Where-Object {
                    $Destination = $_

                    @(
                        $CriticalServicePatterns |
                            Where-Object {
                                $Destination -like $_
                            }
                    ).Count -gt 0
                }
        )

        $DocumentedMatches = @(
            $AllowedToDelegateTo |
                Where-Object {
                    $Destination = $_

                    @(
                        $DocumentedServicePatterns |
                            Where-Object {
                                $Destination -like $_
                            }
                    ).Count -gt 0
                }
        )

        $ExcludedMatches = @(
            $AllowedToDelegateTo |
                Where-Object {
                    $Destination = $_

                    @(
                        $ExcludedServicePatterns |
                            Where-Object {
                                $Destination -like $_
                            }
                    ).Count -gt 0
                }
        )

        $Severity = 'Low'
        $Status = 'Finding'

        if ($Enabled -eq $false) {
            $Severity = 'Informational'
        }
        elseif ($CriticalMatches.Count -gt 0) {
            $Severity = 'High'
        }
        elseif (
            $AllowedToDelegateTo.Count -gt 1 -or
            (
                $DocumentedServicePatterns.Count -gt 0 -and
                $DocumentedMatches.Count -ne $AllowedToDelegateTo.Count
            )
        ) {
            $Severity = 'Medium'
        }

        if (
            $ExcludedMatches.Count -eq $AllowedToDelegateTo.Count -and
            $ExcludedMatches.Count -gt 0
        ) {
            $Severity = 'Informational'
            $Status = 'NotApplicable'
        }

        $Confidence = 'High'

        if (
            -not $HasCompleteUac -or
            [string]::IsNullOrWhiteSpace($DistinguishedName) -or
            [string]::IsNullOrWhiteSpace($Name)
        ) {
            $Confidence = 'Medium'
        }

        $Evidence = [PSCustomObject][ordered]@{
            AllowedToDelegateTo   = $AllowedToDelegateTo
            ServicePrincipalNames = $ServicePrincipalNames
            AccountEnabled        = $Enabled
            UserAccountControl    = $UserAccountControl
            CriticalMatches       = $CriticalMatches
            DocumentedMatches     = $DocumentedMatches
            ExcludedMatches       = $ExcludedMatches
            ProviderStatus        = $ProviderStatus
        }

        $Risk =
            'The delegation configuration should be reviewed because a compromised delegating account could affect authentication to the listed services.'

        if ($Enabled -eq $false) {
            $Risk =
                'The account is disabled, but the delegation configuration should be reviewed before the account is enabled.'
        }
        elseif ($CriticalMatches.Count -gt 0) {
            $Risk =
                'The delegation targets a service matched by the supplied sensitive-service patterns and requires priority review.'
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Title ('Constrained delegation on {0}' -f $Name) `
            -Description 'The account is configured with one or more constrained delegation service principals.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status $Status `
            -AffectedObject (
                [PSCustomObject][ordered]@{
                    Name        = $Name
                    ObjectClass = $ObjectType
                    Enabled     = $Enabled
                }
            ) `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk $Risk `
            -Recommendation 'Review the business requirement, minimize delegation destinations, remove stale SPNs, and document approved exceptions.' `
            -References @(
                'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}