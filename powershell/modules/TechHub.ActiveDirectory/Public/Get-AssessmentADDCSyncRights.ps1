function Get-AssessmentADDCSyncRights {
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
        [string[]]$ApprovedPrincipalPatterns = @(
            '*\Domain Admins'
            '*\Enterprise Admins'
            '*\Administrators'
            '*\Domain Controllers'
            '*\Enterprise Domain Controllers'
            'NT AUTHORITY\SYSTEM'
            'NT AUTHORITY\Enterprise Domain Controllers'
        ),

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-DCSYNC-RIGHTS'
    $CheckName = 'DCSync Replication Rights'
    $GetChangesGuid = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $GetChangesAllGuid = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    $AllObjectsGuid = [guid]::Empty

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

    $DomainDN = $null

    if (
        $null -ne $DomainResult -and
        $DomainResult.Status -eq 'Available' -and
        @($DomainResult.Data).Count -gt 0
    ) {
        $DomainData = @($DomainResult.Data)[0]

        if ($null -ne $DomainData.PSObject.Properties['DNSRoot']) {
            if ([string]::IsNullOrWhiteSpace($Domain)) {
                $Domain = [string]$DomainData.PSObject.Properties['DNSRoot'].Value
            }
        }

        if ($null -ne $DomainData.PSObject.Properties['DistinguishedName']) {
            $DomainDN = [string]$DomainData.PSObject.Properties['DistinguishedName'].Value
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

    if ([string]::IsNullOrWhiteSpace($DomainDN)) {
        Write-Verbose -Message 'Unable to determine the domain root distinguished name from the provider.'

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'PrivilegedAccess' `
            -Title 'DCSync rights assessment unavailable' `
            -Description 'The domain root distinguished name could not be determined, so the domain ACL could not be assessed.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $(if ($null -ne $DomainResult) { [string]$DomainResult.Status } else { 'NotAvailable' }) `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $null; ObjectClass = 'Domain'; Enabled = $null }) `
            -ObjectType 'Domain' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $(if ($null -ne $DomainResult) { $DomainResult.Status } else { $null }) }) `
            -Risk 'No security conclusion can be made because the domain root could not be identified.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://attack.mitre.org/techniques/T1003/006/') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    try {
        Write-Verbose -Message ('Requesting the security descriptor of {0} from TechHubADProvider.' -f $DomainDN)
        $AclResult = $Provider.GetObjectSecurityDescriptor($DomainDN)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    if ($null -eq $AclResult) {
        Write-Error -Message 'TechHubADProvider returned no operation result.'
        return
    }

    $AclStatus = [string]$AclResult.Status

    if ($AclStatus -eq 'NotAvailable' -or $AclStatus -eq 'Error') {
        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'PrivilegedAccess' `
            -Title 'DCSync rights assessment unavailable' `
            -Description 'The provider could not retrieve the domain root security descriptor.' `
            -Severity 'Informational' `
            -Confidence 'High' `
            -Status $AclStatus `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $null; ObjectClass = 'Domain'; Enabled = $null }) `
            -ObjectType 'Domain' `
            -DistinguishedName $DomainDN `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $AclStatus; ErrorType = $AclResult.ErrorType; ErrorMessage = $AclResult.ErrorMessage }) `
            -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
            -Recommendation 'Restore provider availability and rerun the assessment.' `
            -References @('https://attack.mitre.org/techniques/T1003/006/') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $ReplicationAces = @(
        @($AclResult.Data) |
            Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                [string]$_.ActiveDirectoryRights -match 'ExtendedRight' -and
                (
                    $_.ObjectTypeGuid -eq $GetChangesGuid -or
                    $_.ObjectTypeGuid -eq $GetChangesAllGuid -or
                    $_.ObjectTypeGuid -eq $AllObjectsGuid
                )
            }
    )

    $Grants = @{}

    foreach ($Ace in $ReplicationAces) {

        $Identity = [string]$Ace.IdentityReference

        if ([string]::IsNullOrWhiteSpace($Identity)) {
            continue
        }

        if (-not $Grants.ContainsKey($Identity)) {
            $Grants[$Identity] = [PSCustomObject]@{
                Identity        = $Identity
                HasGetChanges   = $false
                HasGetChangesAll = $false
            }
        }

        if ($Ace.ObjectTypeGuid -eq $GetChangesGuid -or $Ace.ObjectTypeGuid -eq $AllObjectsGuid) {
            $Grants[$Identity].HasGetChanges = $true
        }

        if ($Ace.ObjectTypeGuid -eq $GetChangesAllGuid -or $Ace.ObjectTypeGuid -eq $AllObjectsGuid) {
            $Grants[$Identity].HasGetChangesAll = $true
        }
    }

    foreach ($Identity in $Grants.Keys) {

        $Grant = $Grants[$Identity]

        if (
            @(
                $ApprovedPrincipalPatterns |
                    Where-Object {
                        $Identity -like $_
                    }
            ).Count -gt 0
        ) {
            Write-Verbose -Message ('Skipping {0} because it matches an approved principal pattern.' -f $Identity)
            continue
        }

        $HasFullDCSync = ($Grant.HasGetChanges -and $Grant.HasGetChangesAll)

        $Severity = 'High'
        $Confidence = 'High'

        if ($HasFullDCSync) {
            $Severity = 'Critical'
        }

        $Risk =
            'This principal holds only one of the two rights required for DCSync; combined with the other right (directly or through group membership) it could extract password hashes for every account in the domain, including krbtgt.'

        if ($HasFullDCSync) {
            $Risk =
                'This principal holds both replication rights required for DCSync (Get-Changes and Get-Changes-All) and can extract password hashes for every account in the domain, including krbtgt, without ever touching a domain controller directly.'
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'PrivilegedAccess' `
            -Title ('Replication rights granted to {0}' -f $Identity) `
            -Description 'A principal outside the expected default holders has directory replication rights on the domain root.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Identity; ObjectClass = 'Principal'; Enabled = $null }) `
            -ObjectType 'Principal' `
            -DistinguishedName $DomainDN `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    Identity         = $Identity
                    HasGetChanges    = $Grant.HasGetChanges
                    HasGetChangesAll = $Grant.HasGetChangesAll
                    HasFullDCSync    = $HasFullDCSync
                    DomainDN         = $DomainDN
                    ProviderStatus   = $AclStatus
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Remove the replication right from any principal that is not a domain controller or a documented, approved replication account (for example, a monitored password-sync service).' `
            -References @(
                'https://attack.mitre.org/techniques/T1003/006/'
                'https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
