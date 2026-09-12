function Get-AssessmentADKerberoasting {
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
        [string[]]$ExcludedAccountPatterns = @(),

        [Parameter()]
        [int]$StalePasswordDays = 365,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-KERBEROASTING'
    $CheckName = 'Kerberoasting Exposure'
    $AccountDisabled = [int64]0x2
    $AesEncryptionTypes = [int]0x18

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
        'PasswordLastSet'
        'AdminCount'
        'msDS-SupportedEncryptionTypes'
    )

    $LdapFilter = '(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user))'

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
            'Requesting SPN-bearing user accounts from TechHubADProvider.'

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
            -Category 'Kerberos' `
            -Title 'Kerberoasting assessment unavailable' `
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
                    ProviderStatus         = $ProviderStatus
                    ErrorType              = $ObjectsResult.ErrorType
                    ErrorMessage           = $ObjectsResult.ErrorMessage
                    ServicePrincipalNames  = @()
                    AccountEnabled         = $null
                    AdminCount             = $null
                    WeakEncryptionSupported = $null
                }
            ) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @(
                'https://attack.mitre.org/techniques/T1558/003/'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    Write-Verbose -Message (
        'Provider returned {0} SPN-bearing user account(s).' -f
        $Objects.Count
    )

    foreach ($Object in $Objects) {

        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = [guid]::Empty
        $ServicePrincipalNames = @()
        $UserAccountControl = $null
        $HasCompleteUac = $false
        $PasswordLastSet = $null
        $AdminCount = 0
        $SupportedEncryptionTypes = $null

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

        if ($null -ne $Object.PSObject.Properties['ServicePrincipalName']) {
            $ServicePrincipalNames = @(
                $Object.PSObject.Properties['ServicePrincipalName'].Value |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        }

        if ($ServicePrincipalNames.Count -eq 0) {
            Write-Verbose -Message (
                'Skipping object {0} because no service principal name was returned.' -f
                $Name
            )
            continue
        }

        if (
            @(
                $ExcludedAccountPatterns |
                    Where-Object {
                        $SamAccountName -like $_
                    }
            ).Count -gt 0
        ) {
            Write-Verbose -Message (
                'Skipping object {0} because it matches an excluded account pattern.' -f
                $Name
            )
            continue
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

        if (
            $null -ne $Object.PSObject.Properties['AdminCount'] -and
            $null -ne $Object.PSObject.Properties['AdminCount'].Value
        ) {
            try {
                $AdminCount = [int]$Object.PSObject.Properties['AdminCount'].Value
            }
            catch {
                $AdminCount = 0
            }
        }

        $IsPrivileged = ($AdminCount -eq 1)

        $HasEncryptionData = $false

        if ($null -ne $Object.PSObject.Properties['msDS-SupportedEncryptionTypes']) {
            $RawEncryptionTypes = $Object.PSObject.Properties['msDS-SupportedEncryptionTypes'].Value

            if ($null -ne $RawEncryptionTypes) {
                try {
                    $SupportedEncryptionTypes = [int]$RawEncryptionTypes
                    $HasEncryptionData = $true
                }
                catch {
                    Write-Verbose `
                        -Message 'Provider returned an invalid msDS-SupportedEncryptionTypes.'
                }
            }
        }

        $WeakEncryptionSupported = (
            (-not $HasEncryptionData) -or
            (($SupportedEncryptionTypes -band $AesEncryptionTypes) -eq 0)
        )

        $Severity = 'Low'

        if ($Enabled -eq $false) {
            $Severity = 'Informational'
        }
        elseif ($IsPrivileged -and $WeakEncryptionSupported) {
            $Severity = 'Critical'
        }
        elseif ($IsPrivileged -or $WeakEncryptionSupported) {
            $Severity = 'Medium'
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
            ServicePrincipalNames   = $ServicePrincipalNames
            AccountEnabled          = $Enabled
            UserAccountControl      = $UserAccountControl
            PasswordLastSet         = $PasswordLastSet
            PasswordAgeDays         = $PasswordAgeDays
            AdminCount              = $AdminCount
            IsPrivileged            = $IsPrivileged
            SupportedEncryptionTypes = $SupportedEncryptionTypes
            WeakEncryptionSupported = $WeakEncryptionSupported
            ProviderStatus          = $ProviderStatus
        }

        $Risk =
            'The account exposes a service principal name and can be requested for a Kerberos service ticket by any authenticated principal; an offline attack against the ticket can attempt to recover the account password.'

        if ($IsPrivileged -and $WeakEncryptionSupported) {
            $Risk =
                'The account is privileged (adminCount=1), exposes a service principal name, and does not require AES; a successful offline attack could yield privileged domain credentials.'
        }
        elseif ($WeakEncryptionSupported) {
            $Risk =
                'The service ticket for this account can be requested using RC4, which is significantly weaker to attack offline than AES.'
        }
        elseif ($IsPrivileged) {
            $Risk =
                'The account is privileged (adminCount=1) and remains a high-value Kerberoasting target even though AES encryption is supported.'
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Kerberos' `
            -Title ('Kerberoastable account {0}' -f $Name) `
            -Description 'The account has a service principal name and can be targeted for Kerberoasting.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status 'Finding' `
            -AffectedObject (
                [PSCustomObject][ordered]@{
                    Name        = $Name
                    ObjectClass = 'User'
                    Enabled     = $Enabled
                }
            ) `
            -ObjectType 'User' `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk $Risk `
            -Recommendation 'Use a group Managed Service Account where possible, enforce AES-only Kerberos encryption, and use a long, randomly generated password rotated regularly for accounts that must remain SPN-bearing.' `
            -References @(
                'https://attack.mitre.org/techniques/T1558/003/'
                'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
