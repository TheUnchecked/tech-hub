function Get-AssessmentADASREPRoasting {
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
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-ASREP-ROASTING'
    $CheckName = 'AS-REP Roasting Exposure'
    $AccountDisabled = [int64]0x2
    $DontRequirePreauth = [int64]0x400000

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
    )

    $LdapFilter = '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(objectCategory=person)(objectClass=user))'

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
            'Requesting accounts with DONT_REQUIRE_PREAUTH from TechHubADProvider.'

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
            -Title 'AS-REP Roasting assessment unavailable' `
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
                    ProviderStatus = $ProviderStatus
                    ErrorType      = $ObjectsResult.ErrorType
                    ErrorMessage   = $ObjectsResult.ErrorMessage
                    AccountEnabled = $null
                    AdminCount     = $null
                }
            ) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @(
                'https://attack.mitre.org/techniques/T1558/004/'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    Write-Verbose -Message (
        'Provider returned {0} account(s) with DONT_REQUIRE_PREAUTH.' -f
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

        if ($null -ne $Object.PSObject.Properties['Name']) {
            $Name = [string]$Object.PSObject.Properties['Name'].Value
        }

        if ($null -ne $Object.PSObject.Properties['DistinguishedName']) {
            $DistinguishedName = [string]$Object.PSObject.Properties['DistinguishedName'].Value
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
            Write-Verbose -Message (
                'Skipping object {0} because it matches an excluded account pattern.' -f
                $Name
            )
            continue
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

        if ($HasCompleteUac -and (($UserAccountControl -band $DontRequirePreauth) -eq 0)) {
            continue
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

        $Severity = 'High'

        if ($Enabled -eq $false) {
            $Severity = 'Informational'
        }
        elseif ($IsPrivileged) {
            $Severity = 'Critical'
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
            UserAccountControl     = $UserAccountControl
            DontRequirePreauth     = (($HasCompleteUac) -and (($UserAccountControl -band $DontRequirePreauth) -ne 0))
            AccountEnabled         = $Enabled
            PasswordLastSet        = $PasswordLastSet
            ServicePrincipalNames  = $ServicePrincipalNames
            AdminCount             = $AdminCount
            IsPrivileged           = $IsPrivileged
            ProviderStatus         = $ProviderStatus
        }

        $Risk =
            'Any unauthenticated attacker can request an AS-REP for this account and attempt an offline attack against it without holding valid domain credentials.'

        if ($IsPrivileged) {
            $Risk =
                'The account is privileged (adminCount=1) and does not require Kerberos preauthentication; an unauthenticated attacker can attempt an offline attack against its AS-REP to recover privileged credentials.'
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Kerberos' `
            -Title ('AS-REP roastable account {0}' -f $Name) `
            -Description 'The account is configured with DONT_REQUIRE_PREAUTH and can be targeted for AS-REP roasting.' `
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
            -Recommendation 'Remove the "Do not require Kerberos preauthentication" setting unless there is a documented, compensating-controlled business requirement.' `
            -References @(
                'https://attack.mitre.org/techniques/T1558/004/'
                'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
