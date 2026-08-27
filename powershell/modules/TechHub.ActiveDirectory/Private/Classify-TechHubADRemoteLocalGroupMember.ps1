#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-TechHubADRemoteLocalGroupMemberClassification {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Member,

        [Parameter()]
        [AllowEmptyString()]
        [string]$SID,

        [Parameter()]
        [AllowNull()]
        [bool]$LocalAccount = $false
    )

    $MemberValue = [string]$Member
    $SidValue = [string]$SID

    if ([string]::IsNullOrWhiteSpace($MemberValue)) {
        return 'Unknown'
    }

    $MemberValue = $MemberValue.Trim()

    # ============================================================
    # 1. SID CLASSIFICATION
    # ============================================================

    if (-not [string]::IsNullOrWhiteSpace($SidValue)) {

        switch -Regex ($SidValue) {

            '^S-1-1-0$' {
                return 'WellKnownPrincipal'
            }

            '^S-1-5-4$' {
                return 'WellKnownPrincipal'
            }

            '^S-1-5-11$' {
                return 'WellKnownPrincipal'
            }

            '^S-1-5-7$' {
                return 'WellKnownPrincipal'
            }

            '^S-1-5-18$' {
                return 'BuiltInPrincipal'
            }

            '^S-1-5-19$' {
                return 'BuiltInPrincipal'
            }

            '^S-1-5-20$' {
                return 'BuiltInPrincipal'
            }

            '^S-1-5-32-\d+$' {
                return 'BuiltInPrincipal'
            }
        }
    }

    # ============================================================
    # 2. AUTHORITY / ACCOUNT
    # ============================================================

    $Authority = $null
    $AccountName = $MemberValue

    if ($MemberValue -match '^(?<Authority>[^\\]+)\\(?<Account>.+)$') {

        $Authority = $Matches['Authority']
        $AccountName = $Matches['Account']
    }

    $Authority = [string]$Authority
    $AccountName = [string]$AccountName

    # ============================================================
    # 3. WELL-KNOWN AUTHORITIES
    # ============================================================

    if (
        $Authority.Equals(
            'NT AUTHORITY',
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        return 'BuiltInPrincipal'
    }

    if (
        $Authority.Equals(
            'NT SERVICE',
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        return 'BuiltInPrincipal'
    }

    if (
        $Authority.Equals(
            'BUILTIN',
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        return 'BuiltInPrincipal'
    }

    # ============================================================
    # 4. WELL-KNOWN NAMES
    # ============================================================

    $WellKnownNames = @(
        'Everyone'
        'Authenticated Users'
        'INTERACTIVE'
        'NETWORK'
        'LOCAL'
        'CONSOLE LOGON'
        'DIALUP'
        'BATCH'
        'SERVICE'
        'ANONYMOUS LOGON'
        'SELF'
        'CREATOR OWNER'
        'CREATOR GROUP'
        'OWNER RIGHTS'
        'RESTRICTED'
        'REMOTE INTERACTIVE LOGON'
        'WRITE RESTRICTED CODE'
    )

    foreach ($WellKnownName in $WellKnownNames) {

        if (
            $WellKnownName.Equals(
                $AccountName,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return 'WellKnownPrincipal'
        }
    }

    # ============================================================
    # 5. LOCAL ACCOUNT
    # ============================================================

    if ($LocalAccount -eq $true) {
        return 'LocalAccount'
    }

    # ============================================================
    # 6. LOCAL COMPUTER AUTHORITY
    # ============================================================

    if (
        -not [string]::IsNullOrWhiteSpace($Authority) -and
        $Authority.Equals(
            $ComputerName,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        return 'LocalAccount'
    }

    # ============================================================
    # 7. DOMAIN PRINCIPAL
    # ============================================================

    if (
        -not [string]::IsNullOrWhiteSpace($Authority)
    ) {
        return 'DomainPrincipal'
    }

    # ============================================================
    # 8. UNKNOWN
    # ============================================================

    return 'Unknown'
}