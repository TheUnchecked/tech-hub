function Get-AssessmentADPasswordPolicy {
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
        [int]$MinPasswordLengthThreshold = 14,

        [Parameter()]
        [switch]$IncludeFineGrainedPolicies,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-PASSWORD-POLICY'
    $CheckName = 'Password Policy'

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

    function New-TechHubPasswordPolicyFinding {
        param(
            [Parameter(Mandatory)]
            [object]$Policy,

            [Parameter(Mandatory)]
            [string]$PolicyName,

            [Parameter(Mandatory)]
            [string]$ProviderStatus,

            [string]$ErrorType,
            [string]$ErrorMessage
        )

        if ($ProviderStatus -eq 'NotAvailable' -or $ProviderStatus -eq 'Error') {
            return New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Authentication' `
                -Title ('Password policy assessment unavailable for {0}' -f $PolicyName) `
                -Description 'The provider could not retrieve the requested password policy.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status $ProviderStatus `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $PolicyName; ObjectClass = 'PasswordPolicy'; Enabled = $null }) `
                -ObjectType 'PasswordPolicy' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $ProviderStatus; ErrorType = $ErrorType; ErrorMessage = $ErrorMessage }) `
                -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
                -Recommendation 'Restore provider availability and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController
        }

        $MinPasswordLength = $null
        $ComplexityEnabled = $null
        $ReversibleEncryptionEnabled = $null
        $LockoutThreshold = $null
        $PasswordHistoryCount = $null
        $MaxPasswordAge = $null
        $DistinguishedName = $null

        if ($null -ne $Policy.PSObject.Properties['MinPasswordLength']) { $MinPasswordLength = [int]$Policy.MinPasswordLength }
        if ($null -ne $Policy.PSObject.Properties['ComplexityEnabled']) { $ComplexityEnabled = [bool]$Policy.ComplexityEnabled }
        if ($null -ne $Policy.PSObject.Properties['ReversibleEncryptionEnabled']) { $ReversibleEncryptionEnabled = [bool]$Policy.ReversibleEncryptionEnabled }
        if ($null -ne $Policy.PSObject.Properties['LockoutThreshold']) { $LockoutThreshold = [int]$Policy.LockoutThreshold }
        if ($null -ne $Policy.PSObject.Properties['PasswordHistoryCount']) { $PasswordHistoryCount = [int]$Policy.PasswordHistoryCount }
        if ($null -ne $Policy.PSObject.Properties['MaxPasswordAge']) { $MaxPasswordAge = $Policy.MaxPasswordAge }
        if ($null -ne $Policy.PSObject.Properties['DistinguishedName']) { $DistinguishedName = [string]$Policy.DistinguishedName }

        $Weaknesses = @()
        $Severity = 'Informational'

        if ($ReversibleEncryptionEnabled -eq $true) {
            $Weaknesses += 'Passwords are stored using reversible encryption.'
            $Severity = 'Critical'
        }

        if ($ComplexityEnabled -eq $false) {
            $Weaknesses += 'Password complexity is not enforced.'
            if ($Severity -ne 'Critical') { $Severity = 'High' }
        }

        if ($null -ne $LockoutThreshold -and $LockoutThreshold -eq 0) {
            $Weaknesses += 'Account lockout is disabled (LockoutThreshold = 0), allowing unlimited password guesses.'
            if ($Severity -notin @('Critical', 'High')) { $Severity = 'Medium' }
        }

        if ($null -ne $MinPasswordLength -and $MinPasswordLength -lt $MinPasswordLengthThreshold) {
            if ($MinPasswordLength -lt 8) {
                $Weaknesses += ('Minimum password length is {0}, below the widely accepted 8-character floor.' -f $MinPasswordLength)
                if ($Severity -notin @('Critical')) { $Severity = 'High' }
            }
            else {
                $Weaknesses += ('Minimum password length is {0}, below the configured threshold of {1}.' -f $MinPasswordLength, $MinPasswordLengthThreshold)
                if ($Severity -notin @('Critical', 'High')) { $Severity = 'Medium' }
            }
        }

        $Risk = 'The current password policy meets the configured baseline expectations.'

        if ($Weaknesses.Count -gt 0) {
            $Risk = 'A weaker password policy makes password-guessing, spraying, and offline cracking attacks more likely to succeed. Weaknesses: ' + ($Weaknesses -join ' ')
        }

        return New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Authentication' `
            -Title ('Password policy: {0}' -f $PolicyName) `
            -Description 'Evaluates a domain or fine-grained password policy against baseline security expectations.' `
            -Severity $Severity `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $PolicyName; ObjectClass = 'PasswordPolicy'; Enabled = $null }) `
            -ObjectType 'PasswordPolicy' `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    MinPasswordLength           = $MinPasswordLength
                    ComplexityEnabled           = $ComplexityEnabled
                    ReversibleEncryptionEnabled = $ReversibleEncryptionEnabled
                    LockoutThreshold            = $LockoutThreshold
                    PasswordHistoryCount        = $PasswordHistoryCount
                    MaxPasswordAge              = $MaxPasswordAge
                    Weaknesses                  = $Weaknesses
                    ProviderStatus              = $ProviderStatus
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Require at least 14 characters, keep complexity enabled, never enable reversible encryption, and configure a lockout threshold that mitigates brute-force and spray attacks.' `
            -References @(
                'https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/password-policy'
                'https://pages.nist.gov/800-63-4/sp800-63b.html'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }

    try {
        Write-Verbose -Message 'Requesting the default domain password policy from TechHubADProvider.'
        $DefaultPolicyResult = $Provider.GetDefaultDomainPasswordPolicy()
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $DefaultPolicyResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $DefaultPolicyData = @($DefaultPolicyResult.Data)
    $DefaultPolicy = if ($DefaultPolicyData.Count -gt 0) { $DefaultPolicyData[0] } else { [PSCustomObject]@{} }

    New-TechHubPasswordPolicyFinding `
        -Policy $DefaultPolicy `
        -PolicyName 'Default Domain Policy' `
        -ProviderStatus ([string]$DefaultPolicyResult.Status) `
        -ErrorType $DefaultPolicyResult.ErrorType `
        -ErrorMessage $DefaultPolicyResult.ErrorMessage

    if (-not $IncludeFineGrainedPolicies) {
        return
    }

    try {
        Write-Verbose -Message 'Requesting Fine-Grained Password Policies from TechHubADProvider.'
        $FgppResult = $Provider.GetFineGrainedPasswordPolicies()
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $FgppResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $FgppStatus = [string]$FgppResult.Status

    if ($FgppStatus -eq 'NotAvailable' -or $FgppStatus -eq 'Error') {
        New-TechHubPasswordPolicyFinding `
            -Policy ([PSCustomObject]@{}) `
            -PolicyName 'Fine-Grained Password Policies' `
            -ProviderStatus $FgppStatus `
            -ErrorType $FgppResult.ErrorType `
            -ErrorMessage $FgppResult.ErrorMessage

        return
    }

    foreach ($FgppPolicy in @($FgppResult.Data)) {

        $PolicyName = 'Fine-Grained Password Policy'

        if ($null -ne $FgppPolicy.PSObject.Properties['Name']) {
            $PolicyName = [string]$FgppPolicy.PSObject.Properties['Name'].Value
        }

        New-TechHubPasswordPolicyFinding `
            -Policy $FgppPolicy `
            -PolicyName $PolicyName `
            -ProviderStatus $FgppStatus
    }
}
