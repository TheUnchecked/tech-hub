function Get-AssessmentADProtectedUsersCoverage {
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
        [string[]]$PrivilegedGroups = @('Domain Admins', 'Enterprise Admins'),

        [Parameter()]
        [string]$ProtectedUsersGroupName = 'Protected Users',

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-PROTECTED-USERS-COVERAGE'
    $CheckName = 'Protected Users Coverage'

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
        Write-Verbose -Message (
            'Requesting members of {0} from TechHubADProvider.' -f $ProtectedUsersGroupName
        )

        $ProtectedUsersResult = $Provider.GetGroupMembers($ProtectedUsersGroupName)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $ProtectedUsersResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $ProtectedUsersStatus = [string]$ProtectedUsersResult.Status

    if ($ProtectedUsersStatus -eq 'NotAvailable' -or $ProtectedUsersStatus -eq 'Error') {

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Hardening' `
            -Title 'Protected Users coverage assessment unavailable' `
            -Description ('The provider could not retrieve members of {0}.' -f $ProtectedUsersGroupName) `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $ProtectedUsersStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $ProtectedUsersGroupName; ObjectClass = 'Group'; Enabled = $null }) `
            -ObjectType 'Group' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $ProtectedUsersStatus; ErrorType = $ProtectedUsersResult.ErrorType; ErrorMessage = $ProtectedUsersResult.ErrorMessage }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $ProtectedMemberSids = @(
        @($ProtectedUsersResult.Data) |
            ForEach-Object {
                if ($null -ne $_.PSObject.Properties['SID'] -and $null -ne $_.PSObject.Properties['SID'].Value) {
                    [string]$_.PSObject.Properties['SID'].Value
                }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    foreach ($GroupName in $PrivilegedGroups) {

        try {
            Write-Verbose -Message ('Requesting members of {0} from TechHubADProvider.' -f $GroupName)
            $GroupMembersResult = $Provider.GetGroupMembers($GroupName)
        }
        catch {
            Write-Error -ErrorRecord $_
            continue
        }

        if ($null -eq $GroupMembersResult) {
            Write-Error -Message 'TechHubADProvider returned no operation result.'
            continue
        }

        $GroupStatus = [string]$GroupMembersResult.Status

        if ($GroupStatus -eq 'NotAvailable' -or $GroupStatus -eq 'Error') {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('Protected Users coverage assessment unavailable for {0}' -f $GroupName) `
                -Description 'The provider could not retrieve the membership of this privileged group.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status $GroupStatus `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $GroupName; ObjectClass = 'Group'; Enabled = $null }) `
                -ObjectType 'Group' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $GroupStatus; ErrorType = $GroupMembersResult.ErrorType; ErrorMessage = $GroupMembersResult.ErrorMessage }) `
                -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
                -Recommendation 'Restore provider availability and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        foreach ($Member in @($GroupMembersResult.Data)) {

            $MemberObjectClass = $null
            $MemberSid = $null
            $MemberName = $null
            $MemberSamAccountName = $null
            $MemberDn = $null

            if ($null -ne $Member.PSObject.Properties['ObjectClass']) {
                $MemberObjectClass = [string]$Member.PSObject.Properties['ObjectClass'].Value
            }

            # Protected Users applies to signed-in accounts; nested groups
            # are not themselves signed-in principals.
            if ($MemberObjectClass -eq 'group') {
                continue
            }

            if ($null -ne $Member.PSObject.Properties['SID']) {
                $MemberSid = [string]$Member.PSObject.Properties['SID'].Value
            }

            if ([string]::IsNullOrWhiteSpace($MemberSid)) {
                continue
            }

            if ($ProtectedMemberSids -contains $MemberSid) {
                continue
            }

            if ($null -ne $Member.PSObject.Properties['Name']) {
                $MemberName = [string]$Member.PSObject.Properties['Name'].Value
            }

            if ($null -ne $Member.PSObject.Properties['SamAccountName']) {
                $MemberSamAccountName = [string]$Member.PSObject.Properties['SamAccountName'].Value
            }

            if ($null -ne $Member.PSObject.Properties['DistinguishedName']) {
                $MemberDn = [string]$Member.PSObject.Properties['DistinguishedName'].Value
            }

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Hardening' `
                -Title ('{0} member not covered by Protected Users: {1}' -f $GroupName, $MemberName) `
                -Description ('The account is a member of {0} but not of {1}.' -f $GroupName, $ProtectedUsersGroupName) `
                -Severity 'High' `
                -Confidence 'High' `
                -Status 'Finding' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $MemberName; ObjectClass = $MemberObjectClass; Enabled = $null }) `
                -ObjectType $(if ([string]::IsNullOrWhiteSpace($MemberObjectClass)) { 'Unknown' } else { $MemberObjectClass }) `
                -DistinguishedName $MemberDn `
                -SamAccountName $MemberSamAccountName `
                -ObjectGuid ([guid]::Empty) `
                -Evidence (
                    [PSCustomObject][ordered]@{
                        PrivilegedGroup         = $GroupName
                        ProtectedUsersGroupName = $ProtectedUsersGroupName
                        MemberSid               = $MemberSid
                        ProviderStatus          = $GroupStatus
                    }
                ) `
                -Risk 'Without Protected Users membership, this privileged account can authenticate using NTLM, unconstrained/constrained Kerberos delegation, and long-lived Kerberos tickets - all of which are avoided for accounts in the group.' `
                -Recommendation 'Add the account to the Protected Users group after validating application compatibility (Protected Users disables some legacy authentication methods entirely).' `
                -References @('https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController
        }
    }
}
