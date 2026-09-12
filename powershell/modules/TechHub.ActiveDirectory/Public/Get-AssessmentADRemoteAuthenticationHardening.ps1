#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteAuthenticationHardening {
    <#
    .SYNOPSIS
        Evaluates legacy authentication hardening settings on remote
        Windows computers and returns one security finding per computer.

    .DESCRIPTION
        Read-only remote assessment. Reads three registry values through
        CIM's StdRegProv class (no PowerShell remoting, no external
        executable, transport is CIM/WSMan then CIM/DCOM via
        Invoke-AssessmentADRemoteCimQuery):

        - LmCompatibilityLevel (SYSTEM\CurrentControlSet\Control\Lsa)
        - NoLMHash (SYSTEM\CurrentControlSet\Control\Lsa)
        - LDAPServerIntegrity (SYSTEM\CurrentControlSet\Services\NTDS\Parameters),
          evaluated only when present (domain controllers only).

        When -ComputerName is not supplied, targets are discovered with
        Get-AssessmentADRemoteTargets (default -TargetType DomainController,
        since these settings matter most on domain controllers).

    .PARAMETER ComputerName
        Explicit list of computers to assess. Bypasses automatic discovery.

    .PARAMETER TargetType
        Discovery scope used when -ComputerName is not supplied. Defaults
        to 'DomainController'.

    .PARAMETER Credential
        Optional alternate credential for the remote CIM connection.

    .PARAMETER UseSSL
        Requests the WSMan transport over HTTPS.

    .PARAMETER Server
        Domain controller used to build a provider for target discovery,
        when -Provider is not supplied.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider, used for target discovery.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$TargetType = 'DomainController',

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$UseSSL,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-AUTH-HARDENING'
    $CheckName = 'Legacy Authentication Hardening'

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('ComputerName')) {

        $Targets = @(
            $ComputerName |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    else {

        if ($null -eq $Provider) {
            $Provider = New-AssessmentADProvider -Server $Server
        }

        try {
            Write-Verbose -Message ('Discovering remote targets (TargetType = {0}).' -f $TargetType)

            $Targets = @(
                Get-AssessmentADRemoteTargets -Provider $Provider -TargetType $TargetType |
                    ForEach-Object { [string]$_.ComputerName } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        catch {
            Write-Error -ErrorRecord $_
            return
        }
    }

    if ($Targets.Count -eq 0) {

        Write-Verbose -Message 'No targets were supplied or discovered; nothing to assess.'
        return
    }

    foreach ($Target in $Targets) {

        Write-Verbose -Message "[$Target] Collecting authentication hardening settings."

        $CimQueryParams = @{
            ComputerName = $Target
            UseSSL       = $UseSSL
            ScriptBlock  = {
                param($Session)

                $HKLM = [uint32]2147483650

                $LmCompat = Invoke-CimMethod `
                    -CimSession $Session `
                    -Namespace 'root/default' `
                    -ClassName StdRegProv `
                    -MethodName GetDWORDValue `
                    -Arguments @{
                        hDefKey     = $HKLM
                        sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Lsa'
                        sValueName  = 'LmCompatibilityLevel'
                    }

                $NoLmHash = Invoke-CimMethod `
                    -CimSession $Session `
                    -Namespace 'root/default' `
                    -ClassName StdRegProv `
                    -MethodName GetDWORDValue `
                    -Arguments @{
                        hDefKey     = $HKLM
                        sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Lsa'
                        sValueName  = 'NoLmHash'
                    }

                $LdapIntegrity = Invoke-CimMethod `
                    -CimSession $Session `
                    -Namespace 'root/default' `
                    -ClassName StdRegProv `
                    -MethodName GetDWORDValue `
                    -Arguments @{
                        hDefKey     = $HKLM
                        sSubKeyName = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                        sValueName  = 'LDAPServerIntegrity'
                    }

                [PSCustomObject][ordered]@{
                    LmCompatibilityLevel       = if ($LmCompat.ReturnValue -eq 0) { [int]$LmCompat.uValue } else { $null }
                    NoLmHash                   = if ($NoLmHash.ReturnValue -eq 0) { [int]$NoLmHash.uValue } else { $null }
                    LdapServerIntegrity        = if ($LdapIntegrity.ReturnValue -eq 0) { [int]$LdapIntegrity.uValue } else { $null }
                    LdapServerIntegrityChecked = ($LdapIntegrity.ReturnValue -eq 0)
                }
            }
        }

        if ($PSBoundParameters.ContainsKey('Credential')) {
            $CimQueryParams.Credential = $Credential
        }

        try {
            $TransportResult = Invoke-AssessmentADRemoteCimQuery @CimQueryParams
        }
        catch {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('Authentication hardening assessment unavailable for {0}' -f $Target) `
                -Description 'The remote registry values required for this check could not be read.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ErrorType = 'RemoteQueryError'; ErrorMessage = $_.Exception.Message }) `
                -Risk 'No security conclusion can be made because the required remote data was unavailable.' `
                -Recommendation 'Verify remote management connectivity (WinRM or DCOM) to the target and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys') `
                -Domain $null `
                -Forest $null `
                -DomainController $null

            continue
        }

        if ($TransportResult.Status -ne 'Available') {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('Authentication hardening assessment unavailable for {0}' -f $Target) `
                -Description 'The remote registry values required for this check could not be read.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ErrorType = $TransportResult.ErrorType; ErrorMessage = $TransportResult.ErrorMessage }) `
                -Risk 'No security conclusion can be made because the required remote data was unavailable.' `
                -Recommendation 'Verify remote management connectivity (WinRM or DCOM) to the target and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys') `
                -Domain $null `
                -Forest $null `
                -DomainController $null

            continue
        }

        $Data = $TransportResult.Data

        $LmCompatibilityLevel = $Data.LmCompatibilityLevel
        $NoLmHashEnabled = if ($null -ne $Data.NoLmHash) { $Data.NoLmHash -eq 1 } else { $null }
        $LdapServerIntegrity = $Data.LdapServerIntegrity

        $Weaknesses = @()

        if ($null -eq $LmCompatibilityLevel -or $LmCompatibilityLevel -lt 3) {
            $Weaknesses += 'LmCompatibilityLevel is not explicitly hardened (expected 5 - Send NTLMv2 response only, refuse LM and NTLM).'
        }
        elseif ($LmCompatibilityLevel -lt 5) {
            $Weaknesses += ('LmCompatibilityLevel is {0}; NTLM/LM fallback is still permitted at the domain controller (expected 5).' -f $LmCompatibilityLevel)
        }

        if ($NoLmHashEnabled -ne $true) {
            $Weaknesses += 'LM hash storage is not explicitly disabled (NoLmHash is not set to 1).'
        }

        if ($Data.LdapServerIntegrityChecked -and $LdapServerIntegrity -ne 2) {
            $Weaknesses += ('LDAPServerIntegrity is {0}; LDAP signing is not required (expected 2).' -f $LdapServerIntegrity)
        }

        $Severity = 'Informational'

        if ($NoLmHashEnabled -ne $true) {
            $Severity = 'High'
        }
        elseif ($Weaknesses.Count -gt 0) {
            $Severity = 'Medium'
        }

        $Risk = 'The evaluated authentication settings meet the hardening baseline.'

        if ($Weaknesses.Count -gt 0) {
            $Risk = 'Weak legacy authentication settings make credential relay, NTLM downgrade, and offline hash-cracking attacks easier. Weaknesses: ' + ($Weaknesses -join ' ')
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Hardening' `
            -Title ('Authentication hardening: {0}' -f $Target) `
            -Description 'Evaluates legacy authentication (LM/NTLM) and LDAP signing hardening settings.' `
            -Severity $Severity `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
            -ObjectType 'Computer' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    LmCompatibilityLevel = $LmCompatibilityLevel
                    NoLmHashEnabled      = $NoLmHashEnabled
                    LdapServerIntegrity  = $LdapServerIntegrity
                    Weaknesses           = $Weaknesses
                    CollectionMethod     = $TransportResult.Transport
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Set LmCompatibilityLevel to 5, NoLmHash to 1, and (on domain controllers) LDAPServerIntegrity to 2, after validating no legacy clients depend on the weaker settings.' `
            -References @(
                'https://learn.microsoft.com/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys'
                'https://learn.microsoft.com/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server'
            ) `
            -Domain $null `
            -Forest $null `
            -DomainController $null
    }
}
