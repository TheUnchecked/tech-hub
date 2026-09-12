function Get-AssessmentADUnconstrainedDelegation {
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
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-UNCONSTRAINED-DELEGATION'
    $CheckName = 'Unconstrained Delegation'
    $TrustedForDelegation = [int64]0x80000
    $AccountDisabled = [int64]0x2
    $Properties = @('DistinguishedName', 'Name', 'ObjectGUID', 'ObjectClass', 'ObjectCategory', 'SamAccountName', 'UserAccountControl', 'ServicePrincipalName', 'Enabled')
    $LdapFilter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(|(objectCategory=computer)(objectCategory=person)))'

    if ($null -eq $Provider) {
        $Provider = New-AssessmentADProvider -Server $Server
    }

    $DomainResult = $null
    $ForestResult = $null
    try { $DomainResult = $Provider.GetDomainInformation() }
    catch { Write-Verbose -Message ('Unable to collect domain context from provider: {0}' -f $_.Exception.Message) }
    try { $ForestResult = $Provider.GetForestInformation() }
    catch { Write-Verbose -Message ('Unable to collect forest context from provider: {0}' -f $_.Exception.Message) }

    if ([string]::IsNullOrWhiteSpace($Domain) -and $null -ne $DomainResult -and $DomainResult.Status -eq 'Available' -and @($DomainResult.Data).Count -gt 0) {
        $DomainData = @($DomainResult.Data)[0]
        if ($null -ne $DomainData.PSObject.Properties['DNSRoot']) { $Domain = [string]$DomainData.PSObject.Properties['DNSRoot'].Value }
    }
    if ([string]::IsNullOrWhiteSpace($Forest) -and $null -ne $ForestResult -and $ForestResult.Status -eq 'Available' -and @($ForestResult.Data).Count -gt 0) {
        $ForestData = @($ForestResult.Data)[0]
        if ($null -ne $ForestData.PSObject.Properties['Name']) { $Forest = [string]$ForestData.PSObject.Properties['Name'].Value }
    }
    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        $DomainController = $Server
        if ([string]::IsNullOrWhiteSpace($DomainController) -and $null -ne $Provider.PSObject.Properties['Server']) { $DomainController = [string]$Provider.PSObject.Properties['Server'].Value }
    }

    try {
        Write-Verbose -Message 'Requesting unconstrained delegation objects from AssessmentADProvider.'
        $ObjectsResult = $Provider.GetADObjects($LdapFilter, $SearchBase, $Properties)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }
    if ($null -eq $ObjectsResult) {
        Write-Error -Message 'AssessmentADProvider returned no operation result.'
        return
    }

    $ProviderStatus = [string]$ObjectsResult.Status
    $Objects = @($ObjectsResult.Data)
    if ($ProviderStatus -eq 'NotAvailable' -or $ProviderStatus -eq 'Error') {
        Write-Verbose -Message ('Provider could not retrieve required objects: {0}' -f $ObjectsResult.ErrorMessage)
        New-AssessmentADFinding `
            -AssessmentId $AssessmentId -CheckId $CheckId -CheckName $CheckName `
            -Title 'Unconstrained delegation assessment unavailable' `
            -Description 'The provider could not retrieve the Active Directory data required for this check.' `
            -Severity 'Informational' -Confidence 'High' -Status $ProviderStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $null; ObjectClass = $null; Enabled = $null }) `
            -ObjectType 'Unknown' -DistinguishedName $null -SamAccountName $null -ObjectGuid $null `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $ProviderStatus; ErrorType = $ObjectsResult.ErrorType; ErrorMessage = $ObjectsResult.ErrorMessage; UserAccountControl = $null; TrustedForDelegation = $null; AccountEnabled = $null; ServicePrincipalNames = @() }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview') `
            -Domain $Domain -Forest $Forest -DomainController $DomainController
        return
    }

    Write-Verbose -Message ('Provider returned {0} object(s) with TRUSTED_FOR_DELEGATION.' -f $Objects.Count)
    foreach ($Object in $Objects) {
        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = $null
        $ObjectClassValues = @()
        $ObjectCategoryValues = @()
        $ServicePrincipalNames = @()
        $UserAccountControl = $null
        $HasCompleteUac = $false

        if ($null -ne $Object.PSObject.Properties['Name']) { $Name = [string]$Object.PSObject.Properties['Name'].Value }
        if ($null -ne $Object.PSObject.Properties['DistinguishedName']) { $DistinguishedName = [string]$Object.PSObject.Properties['DistinguishedName'].Value }
        if ($null -ne $Object.PSObject.Properties['SamAccountName']) { $SamAccountName = [string]$Object.PSObject.Properties['SamAccountName'].Value }
        if ($null -ne $Object.PSObject.Properties['ObjectGUID']) { try { $ObjectGuid = [guid]$Object.PSObject.Properties['ObjectGUID'].Value } catch { Write-Verbose -Message 'Provider returned an invalid ObjectGUID.' } }
        if ($null -ne $Object.PSObject.Properties['ObjectClass']) { $ObjectClassValues = @($Object.PSObject.Properties['ObjectClass'].Value) }
        if ($null -ne $Object.PSObject.Properties['ObjectCategory']) { $ObjectCategoryValues = @($Object.PSObject.Properties['ObjectCategory'].Value) }
        if ($null -ne $Object.PSObject.Properties['ServicePrincipalName']) { $ServicePrincipalNames = @($Object.PSObject.Properties['ServicePrincipalName'].Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
        if ($null -ne $Object.PSObject.Properties['UserAccountControl']) { try { $UserAccountControl = [int64]$Object.PSObject.Properties['UserAccountControl'].Value; $HasCompleteUac = $true } catch { Write-Verbose -Message 'Provider returned an invalid UserAccountControl.' } }
        if ($HasCompleteUac -and (($UserAccountControl -band $TrustedForDelegation) -eq 0)) { continue }

        $ObjectType = 'Unknown'
        if ($ObjectClassValues -contains 'computer') { $ObjectType = 'Computer' }
        elseif ($ObjectClassValues -contains 'user') { $ObjectType = 'User' }
        elseif ($ObjectCategoryValues -match 'computer') { $ObjectType = 'Computer' }
        elseif ($ObjectCategoryValues -match 'person') { $ObjectType = 'User' }

        $Enabled = $null
        if ($null -ne $Object.PSObject.Properties['Enabled'] -and $null -ne $Object.PSObject.Properties['Enabled'].Value) { $Enabled = [bool]$Object.PSObject.Properties['Enabled'].Value }
        elseif ($HasCompleteUac) { $Enabled = (($UserAccountControl -band $AccountDisabled) -eq 0) }

        $Severity = 'High'
        if ($Enabled -eq $false) { $Severity = 'Medium' }
        $Confidence = 'High'
        if (-not $HasCompleteUac -or [string]::IsNullOrWhiteSpace($DistinguishedName)) { $Confidence = 'Medium' }
        $Evidence = [PSCustomObject][ordered]@{
            UserAccountControl = $UserAccountControl
            TrustedForDelegation = (($HasCompleteUac) -and (($UserAccountControl -band $TrustedForDelegation) -ne 0))
            AccountEnabled = $Enabled
            ServicePrincipalNames = $ServicePrincipalNames
            ProviderStatus = $ProviderStatus
        }
        New-AssessmentADFinding `
            -AssessmentId $AssessmentId -CheckId $CheckId -CheckName $CheckName `
            -Title ('Unconstrained delegation on {0}' -f $Name) `
            -Description 'The account is configured for unconstrained Kerberos delegation.' `
            -Severity $Severity -Confidence $Confidence -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Name; ObjectClass = $ObjectType; Enabled = $Enabled }) `
            -ObjectType $ObjectType -DistinguishedName $DistinguishedName -SamAccountName $SamAccountName -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk 'If this enabled account is compromised, Kerberos authentications to the account can increase the impact of the compromise.' `
            -Recommendation 'Review the business requirement, remove unconstrained delegation when it is not required, and prefer a narrowly scoped delegation model.' `
            -References @('https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview') `
            -Domain $Domain -Forest $Forest -DomainController $DomainController
    }
}
