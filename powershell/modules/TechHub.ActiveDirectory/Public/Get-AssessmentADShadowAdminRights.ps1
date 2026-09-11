function Get-AssessmentADShadowAdminRights {
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
            '*\SYSTEM'
            '*\Enterprise Domain Controllers'
            'NT AUTHORITY\SYSTEM'
        ),

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-SHADOW-ADMIN'
    $CheckName = 'Shadow Admin Rights'
    $HighImpactRightsPattern = 'GenericAll|WriteDacl|WriteOwner'
    $WritePropertyRightsPattern = 'GenericWrite'
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
            -Title 'Shadow admin assessment unavailable' `
            -Description 'The domain root distinguished name could not be determined, so ACLs could not be assessed.' `
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
            -References @('https://attack.mitre.org/techniques/T1098/') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController

        return
    }

    $Targets = @(
        [PSCustomObject]@{ Name = 'Domain root'; DistinguishedName = $DomainDN }
        [PSCustomObject]@{ Name = 'AdminSDHolder'; DistinguishedName = ('CN=AdminSDHolder,CN=System,{0}' -f $DomainDN) }
    )

    foreach ($Target in $Targets) {

        try {
            Write-Verbose -Message ('Requesting the security descriptor of {0} from TechHubADProvider.' -f $Target.DistinguishedName)
            $AclResult = $Provider.GetObjectSecurityDescriptor($Target.DistinguishedName)
        }
        catch {
            Write-Error -ErrorRecord $_
            continue
        }

        if ($null -eq $AclResult) {
            Write-Error -Message 'TechHubADProvider returned no operation result.'
            continue
        }

        $AclStatus = [string]$AclResult.Status

        if ($AclStatus -eq 'NotAvailable' -or $AclStatus -eq 'Error') {
            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'PrivilegedAccess' `
                -Title ('Shadow admin assessment unavailable for {0}' -f $Target.Name) `
                -Description 'The provider could not retrieve the security descriptor for this object.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status $AclStatus `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target.Name; ObjectClass = 'Object'; Enabled = $null }) `
                -ObjectType 'Object' `
                -DistinguishedName $Target.DistinguishedName `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ProviderStatus = $AclStatus; ErrorType = $AclResult.ErrorType; ErrorMessage = $AclResult.ErrorMessage }) `
                -Risk 'No security conclusion can be made because the required provider data was unavailable.' `
                -Recommendation 'Restore provider availability and rerun the assessment.' `
                -References @('https://attack.mitre.org/techniques/T1098/') `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        $DangerousAces = @(
            @($AclResult.Data) |
                Where-Object {
                    $_.AccessControlType -eq 'Allow' -and
                    $_.ObjectTypeGuid -eq $AllObjectsGuid -and
                    (
                        [string]$_.ActiveDirectoryRights -match $HighImpactRightsPattern -or
                        [string]$_.ActiveDirectoryRights -match $WritePropertyRightsPattern
                    )
                }
        )

        $Grants = @{}

        foreach ($Ace in $DangerousAces) {

            $Identity = [string]$Ace.IdentityReference

            if ([string]::IsNullOrWhiteSpace($Identity)) {
                continue
            }

            if (
                @(
                    $ApprovedPrincipalPatterns |
                        Where-Object {
                            $Identity -like $_
                        }
                ).Count -gt 0
            ) {
                continue
            }

            if (-not $Grants.ContainsKey($Identity)) {
                $Grants[$Identity] = @()
            }

            $Grants[$Identity] += [string]$Ace.ActiveDirectoryRights
        }

        foreach ($Identity in $Grants.Keys) {

            $Rights = @($Grants[$Identity] | Select-Object -Unique)
            $HasHighImpactRight = @($Rights | Where-Object { $_ -match $HighImpactRightsPattern }).Count -gt 0

            $Severity = 'Medium'

            if ($HasHighImpactRight) {
                $Severity = 'High'
            }

            $Risk =
                'This principal can write most non-security properties on the target object; combined with other misconfigurations this can be a path to privilege escalation.'

            if ($HasHighImpactRight) {
                $Risk =
                    'This principal effectively holds administrative control over the target object (full control, ACL modification, or ownership change) without being a documented, expected administrative holder. This is a common "shadow admin" privilege escalation path.'
            }

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'PrivilegedAccess' `
                -Title ('Unexpected administrative rights on {0} for {1}' -f $Target.Name, $Identity) `
                -Description 'A principal outside the expected default holders has GenericAll, WriteDacl, WriteOwner, or GenericWrite rights on a sensitive Active Directory object.' `
                -Severity $Severity `
                -Confidence 'High' `
                -Status 'Finding' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target.Name; ObjectClass = 'Object'; Enabled = $null }) `
                -ObjectType 'Object' `
                -DistinguishedName $Target.DistinguishedName `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence (
                    [PSCustomObject][ordered]@{
                        Identity           = $Identity
                        TargetObject       = $Target.Name
                        TargetDistinguishedName = $Target.DistinguishedName
                        Rights             = $Rights
                        HasHighImpactRight = $HasHighImpactRight
                        ProviderStatus     = $AclStatus
                    }
                ) `
                -Risk $Risk `
                -Recommendation 'Remove the grant unless it is a documented, approved delegation, and prefer a narrowly scoped, audited delegation over broad rights such as GenericAll on the domain root or AdminSDHolder.' `
                -References @(
                    'https://attack.mitre.org/techniques/T1098/'
                    'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory'
                ) `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController
        }
    }
}
