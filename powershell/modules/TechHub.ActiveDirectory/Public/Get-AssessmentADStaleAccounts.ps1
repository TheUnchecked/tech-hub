function Get-AssessmentADStaleAccounts {
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
        [int]$StaleDays = 90,

        [Parameter()]
        [string[]]$ExcludedAccountPatterns = @(),

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-STALE-ACCOUNTS'
    $CheckName = 'Stale Active Directory Accounts'
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
        'LastLogonTimestamp'
        'AdminCount'
    )

    # Negating a bitwise-AND extensible match filter is not reliably
    # supported by Active Directory's LDAP server, so disabled accounts
    # are excluded in PowerShell (via the normalized Enabled property)
    # rather than in the LDAP filter itself.
    $LdapFilter = '(|(objectCategory=computer)(objectCategory=person))'

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
            'Requesting enabled user and computer accounts from TechHubADProvider.'

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
        Write-Error -Message 'TechHubADProvider returned no operation result.'
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
            -Category 'AccountHygiene' `
            -Title 'Stale account assessment unavailable' `
            -Description 'The provider could not retrieve the Active Directory data required for this check.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $ProviderStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $null; ObjectClass = 'Unknown'; Enabled = $null }) `
            -ObjectType 'Unknown' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $ProviderStatus; ErrorType = $ObjectsResult.ErrorType; ErrorMessage = $ObjectsResult.ErrorMessage }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    Write-Verbose -Message ('Provider returned {0} enabled account(s) to evaluate.' -f $Objects.Count)

    foreach ($Object in $Objects) {

        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = [guid]::Empty
        $ObjectClassValues = @()
        $ObjectCategoryValues = @()
        $LastLogonTimestamp = $null
        $AdminCount = 0

        if ($null -ne $Object.PSObject.Properties['Name']) {
            $Name = [string]$Object.PSObject.Properties['Name'].Value
        }

        if ($null -ne $Object.PSObject.Properties['SamAccountName']) {
            $SamAccountName = [string]$Object.PSObject.Properties['SamAccountName'].Value
        }

        if (
            @(
                $ExcludedAccountPatterns |
                    Where-Object {
                        $SamAccountName -like $_
                    }
            ).Count -gt 0
        ) {
            Write-Verbose -Message ('Skipping object {0} because it matches an excluded account pattern.' -f $Name)
            continue
        }

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
                    Write-Verbose -Message 'Provider returned an invalid ObjectGUID.'
                }
            }
        }

        if ($null -ne $Object.PSObject.Properties['ObjectClass']) {
            $ObjectClassValues = @($Object.PSObject.Properties['ObjectClass'].Value)
        }

        if ($null -ne $Object.PSObject.Properties['ObjectCategory']) {
            $ObjectCategoryValues = @($Object.PSObject.Properties['ObjectCategory'].Value)
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

        if (
            $null -ne $Object.PSObject.Properties['Enabled'] -and
            $null -ne $Object.PSObject.Properties['Enabled'].Value
        ) {
            $Enabled = [bool]$Object.PSObject.Properties['Enabled'].Value
        }

        if ($Enabled -ne $true) {
            continue
        }

        if (
            $null -ne $Object.PSObject.Properties['LastLogonTimestamp'] -and
            $null -ne $Object.PSObject.Properties['LastLogonTimestamp'].Value
        ) {
            try {
                $LastLogonTimestamp = [datetime]$Object.PSObject.Properties['LastLogonTimestamp'].Value
            }
            catch {
                Write-Verbose -Message 'Provider returned an invalid LastLogonTimestamp.'
            }
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

        if ($null -eq $LastLogonTimestamp) {

            # LastLogonTimestamp is absent (never replicated) - could mean a
            # brand-new account or one that has genuinely never logged on.
            # Report at low confidence rather than assume staleness.
            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'AccountHygiene' `
                -Title ('Account with no recorded logon: {0}' -f $Name) `
                -Description 'The account has never recorded a replicated logon timestamp.' `
                -Severity $(if ($IsPrivileged) { 'Medium' } else { 'Low' }) `
                -Confidence 'Low' `
                -Status 'Finding' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Name; ObjectClass = $ObjectType; Enabled = $true }) `
                -ObjectType $ObjectType `
                -DistinguishedName $DistinguishedName `
                -SamAccountName $SamAccountName `
                -ObjectGuid $ObjectGuid `
                -Evidence (
                    [PSCustomObject][ordered]@{
                        LastLogonTimestamp = $null
                        LastLogonAgeDays   = $null
                        AdminCount         = $AdminCount
                        IsPrivileged       = $IsPrivileged
                        ProviderStatus     = $ProviderStatus
                    }
                ) `
                -Risk 'The account may be newly created and not yet used, or may have never been used and forgotten; verify it is still needed.' `
                -Recommendation 'Confirm the account is still required. Disable or remove it if it is not.' `
                -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        $LastLogonAgeDays = [int]((Get-Date).ToUniversalTime() - $LastLogonTimestamp.ToUniversalTime()).TotalDays

        if ($LastLogonAgeDays -le $StaleDays) {
            continue
        }

        $Severity = 'Medium'

        if ($IsPrivileged) {
            $Severity = 'High'
        }

        $Risk =
            'An enabled but unused account increases the attack surface unnecessarily; if compromised, activity may not be noticed as quickly as on an actively used account.'

        if ($IsPrivileged) {
            $Risk =
                'This account is privileged (adminCount=1) and has not logged on in over {0} days; forgotten privileged access is a common escalation target.' -f $StaleDays
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'AccountHygiene' `
            -Title ('Stale account: {0}' -f $Name) `
            -Description ('The account has not logged on in more than {0} days.' -f $StaleDays) `
            -Severity $Severity `
            -Confidence 'Medium' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Name; ObjectClass = $ObjectType; Enabled = $true }) `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence (
                [PSCustomObject][ordered]@{
                    LastLogonTimestamp = $LastLogonTimestamp
                    LastLogonAgeDays   = $LastLogonAgeDays
                    StaleDaysThreshold = $StaleDays
                    AdminCount         = $AdminCount
                    IsPrivileged       = $IsPrivileged
                    ProviderStatus     = $ProviderStatus
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Confirm the account is still required. Disable or remove it if it is not, or document an exception if it is intentionally dormant (for example, a break-glass account).' `
            -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
