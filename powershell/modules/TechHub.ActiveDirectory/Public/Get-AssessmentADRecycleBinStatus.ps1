function Get-AssessmentADRecycleBinStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

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
    $CheckId = 'AD-RECYCLE-BIN'
    $CheckName = 'Active Directory Recycle Bin'

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
        Write-Verbose -Message 'Requesting the Recycle Bin optional feature from TechHubADProvider.'

        $FeaturesResult = $Provider.GetOptionalFeatures("Name -eq 'Recycle Bin Feature'")
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $FeaturesResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $FeaturesStatus = [string]$FeaturesResult.Status

    if ($FeaturesStatus -eq 'NotAvailable' -or $FeaturesStatus -eq 'Error') {

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'DisasterRecovery' `
            -Title 'Recycle Bin assessment unavailable' `
            -Description 'The provider could not retrieve the Recycle Bin optional feature.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $FeaturesStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = 'Recycle Bin Feature'; ObjectClass = 'OptionalFeature'; Enabled = $null }) `
            -ObjectType 'OptionalFeature' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $FeaturesStatus; ErrorType = $FeaturesResult.ErrorType; ErrorMessage = $FeaturesResult.ErrorMessage }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#adrecycle-bin') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $Feature = @($FeaturesResult.Data) | Select-Object -First 1

    if ($null -eq $Feature) {

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'DisasterRecovery' `
            -Title 'Recycle Bin feature not found' `
            -Description 'The Recycle Bin optional feature does not exist in this forest; the forest functional level may be below Windows Server 2008 R2.' `
            -Severity 'Medium' `
            -Confidence 'Medium' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = 'Recycle Bin Feature'; ObjectClass = 'OptionalFeature'; Enabled = $false }) `
            -ObjectType 'OptionalFeature' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ RecycleBinEnabled = $false; ProviderStatus = $FeaturesStatus }) `
            -Risk 'Without the Recycle Bin feature, restoring an accidentally or maliciously deleted object requires an authoritative restore from backup, which is slower and more disruptive.' `
            -Recommendation 'Raise the forest functional level to Windows Server 2008 R2 or later if compatible with all domain controllers, then enable the Recycle Bin optional feature.' `
            -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#adrecycle-bin') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $EnabledScopes = @()

    if ($null -ne $Feature.PSObject.Properties['EnabledScopes']) {
        $EnabledScopes = @($Feature.PSObject.Properties['EnabledScopes'].Value)
    }

    $RecycleBinEnabled = ($EnabledScopes.Count -gt 0)

    $Severity = 'Informational'
    $Description = 'The Recycle Bin optional feature is enabled.'
    $Risk = 'The Recycle Bin optional feature is enabled, allowing fast, non-authoritative restore of deleted objects.'

    if (-not $RecycleBinEnabled) {
        $Severity = 'Medium'
        $Description = 'The Recycle Bin optional feature exists but is not enabled anywhere in the forest.'
        $Risk = 'Without the Recycle Bin feature enabled, restoring an accidentally or maliciously deleted object requires an authoritative restore from backup, which is slower and more disruptive. Enabling it is a one-way operation that requires the Windows Server 2008 R2 forest functional level.'
    }

    New-AssessmentADFinding `
        -AssessmentId $AssessmentId `
        -CheckId $CheckId `
        -CheckName $CheckName `
        -Category 'DisasterRecovery' `
        -Title 'Active Directory Recycle Bin status' `
        -Description $Description `
        -Severity $Severity `
        -Confidence 'High' `
        -Status 'Finding' `
        -AffectedObject ([PSCustomObject][ordered]@{ Name = 'Recycle Bin Feature'; ObjectClass = 'OptionalFeature'; Enabled = $RecycleBinEnabled }) `
        -ObjectType 'OptionalFeature' `
        -DistinguishedName $null `
        -SamAccountName $null `
        -ObjectGuid ([guid]::Empty) `
        -Evidence (
            [PSCustomObject][ordered]@{
                RecycleBinEnabled = $RecycleBinEnabled
                EnabledScopes     = $EnabledScopes
                ProviderStatus    = $FeaturesStatus
            }
        ) `
        -Risk $Risk `
        -Recommendation 'Enable the Recycle Bin optional feature after confirming the forest functional level supports it (this is a one-way change).' `
        -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#adrecycle-bin') `
        -Domain $Domain `
        -Forest $Forest `
        -DomainController $DomainController
}
