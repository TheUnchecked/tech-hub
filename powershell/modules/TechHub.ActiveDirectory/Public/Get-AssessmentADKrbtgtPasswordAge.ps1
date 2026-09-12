function Get-AssessmentADKrbtgtPasswordAge {
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
        [int]$MaxPasswordAgeDays = 180,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-KRBTGT-PASSWORD-AGE'
    $CheckName = 'krbtgt Password Age'

    $Properties = @(
        'DistinguishedName'
        'Name'
        'ObjectGUID'
        'SamAccountName'
        'PasswordLastSet'
    )

    $LdapFilter = '(sAMAccountName=krbtgt)'

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
            'Requesting the krbtgt account from TechHubADProvider.'

        $ObjectsResult = $Provider.GetADObjects(
            $LdapFilter,
            $null,
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
        $ProviderStatus -eq 'Error' -or
        $Objects.Count -eq 0
    ) {
        Write-Verbose -Message (
            'Provider could not retrieve the krbtgt account: {0}' -f
            $ObjectsResult.ErrorMessage
        )

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Kerberos' `
            -Title 'krbtgt password age assessment unavailable' `
            -Description 'The provider could not retrieve the krbtgt account.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $(if ($Objects.Count -eq 0 -and $ProviderStatus -eq 'Available') { 'Error' } else { $ProviderStatus }) `
            -AffectedObject (
                [PSCustomObject][ordered]@{
                    Name        = 'krbtgt'
                    ObjectClass = 'User'
                    Enabled     = $null
                }
            ) `
            -ObjectType 'User' `
            -DistinguishedName $null `
            -SamAccountName 'krbtgt' `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    ProviderStatus  = $ProviderStatus
                    ErrorType       = $ObjectsResult.ErrorType
                    ErrorMessage    = $ObjectsResult.ErrorMessage
                    PasswordLastSet = $null
                    PasswordAgeDays = $null
                }
            ) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @(
                'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/security-best-practices-for-active-directory-domain-services'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $Object = @($Objects)[0]

    $DistinguishedName = $null
    $ObjectGuid = [guid]::Empty
    $PasswordLastSet = $null

    if ($null -ne $Object.PSObject.Properties['DistinguishedName']) {
        $DistinguishedName = [string]$Object.PSObject.Properties['DistinguishedName'].Value
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

    if (
        $null -ne $Object.PSObject.Properties['PasswordLastSet'] -and
        $null -ne $Object.PSObject.Properties['PasswordLastSet'].Value
    ) {
        try {
            $PasswordLastSet = [datetime]$Object.PSObject.Properties['PasswordLastSet'].Value
        }
        catch {
            Write-Verbose `
                -Message 'Provider returned an invalid PasswordLastSet.'
        }
    }

    $PasswordAgeDays = $null

    if ($null -ne $PasswordLastSet) {
        $PasswordAgeDays = [int]((Get-Date).ToUniversalTime() - $PasswordLastSet.ToUniversalTime()).TotalDays
    }

    $Severity = 'Informational'
    $Confidence = 'High'

    if ($null -eq $PasswordLastSet) {
        $Severity = 'Critical'
        $Confidence = 'Medium'
    }
    elseif ($PasswordAgeDays -gt ($MaxPasswordAgeDays * 2)) {
        $Severity = 'Critical'
    }
    elseif ($PasswordAgeDays -gt $MaxPasswordAgeDays) {
        $Severity = 'High'
    }

    $Risk =
        'The krbtgt account signs and encrypts every Kerberos ticket in the domain; a stale password increases exposure to a golden ticket attack if it is ever compromised, and complicates timely recovery after a compromise.'

    if ($Severity -eq 'Informational') {
        $Risk =
            'The krbtgt password age is within the configured threshold. Rotation should still occur twice, several hours apart, after any suspected domain compromise.'
    }

    New-AssessmentADFinding `
        -AssessmentId $AssessmentId `
        -CheckId $CheckId `
        -CheckName $CheckName `
        -Category 'Kerberos' `
        -Title 'krbtgt password age' `
        -Description 'Reports the age of the krbtgt account password relative to the configured threshold.' `
        -Severity $Severity `
        -Confidence $Confidence `
        -Status 'Finding' `
        -AffectedObject (
            [PSCustomObject][ordered]@{
                Name        = 'krbtgt'
                ObjectClass = 'User'
                Enabled     = $null
            }
        ) `
        -ObjectType 'User' `
        -DistinguishedName $DistinguishedName `
        -SamAccountName 'krbtgt' `
        -ObjectGuid $ObjectGuid `
        -Evidence (
            [PSCustomObject][ordered]@{
                PasswordLastSet    = $PasswordLastSet
                PasswordAgeDays    = $PasswordAgeDays
                MaxPasswordAgeDays = $MaxPasswordAgeDays
                ProviderStatus     = $ProviderStatus
            }
        ) `
        -Risk $Risk `
        -Recommendation 'Rotate the krbtgt password on a regular schedule (or immediately after a suspected compromise), running the rotation twice with a delay of at least the maximum Kerberos ticket lifetime between the two rotations.' `
        -References @(
            'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/security-best-practices-for-active-directory-domain-services'
        ) `
        -Domain $Domain `
        -Forest $Forest `
        -DomainController $DomainController
}
