function Get-AssessmentADPrivilegedGroup {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$GroupPatterns = @(),

        [Parameter()]
        [string[]]$ApprovedMemberPatterns = @(),

        [Parameter()]
        [string[]]$ExcludedMemberPatterns = @(),

        [Parameter()]
        [string[]]$PrivilegedGroupPatterns = @(),

        [Parameter()]
        [string[]]$ServiceAccountPatterns = @(),

        [Parameter()]
        [switch]$IncludeDisabled
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-PRIVILEGED-GROUP'
    $CheckName = 'Privileged Groups'
    $DefaultGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Backup Operators', 'Domain Controllers')
    $AnalysisPatterns = @($DefaultGroups + $GroupPatterns)
    $PrivilegePatterns = @($DefaultGroups + $PrivilegedGroupPatterns)
    $GroupParameters = @{ Filter = '*'; Properties = @('Name', 'SamAccountName', 'DistinguishedName', 'ObjectGUID', 'ObjectClass'); ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $GroupParameters.Server = $Server }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $GroupParameters.SearchBase = $SearchBase }

    $Domain = $null
    $Forest = $null
    $DomainController = $Server
    try {
        $ContextParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) { $ContextParameters.Server = $Server }
        $DomainContext = Get-ADDomain @ContextParameters
        if ($null -ne $DomainContext) { $Domain = $DomainContext.DNSRoot }
    }
    catch { Write-Verbose -Message ('Unable to collect domain context: {0}' -f $_.Exception.Message) }
    try {
        $ContextParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) { $ContextParameters.Server = $Server }
        $ForestContext = Get-ADForest @ContextParameters
        if ($null -ne $ForestContext) { $Forest = $ForestContext.Name }
    }
    catch { Write-Verbose -Message ('Unable to collect forest context: {0}' -f $_.Exception.Message) }

    try {
        Write-Verbose -Message 'Querying Active Directory for privileged groups.'
        $Groups = @(Get-ADGroup @GroupParameters | Where-Object {
            $Group = $_
            $GroupValues = @()
            foreach ($PropertyName in @('Name', 'SamAccountName', 'DistinguishedName')) {
                if ($null -ne $Group.PSObject.Properties[$PropertyName]) {
                    $GroupValues += [string]$Group.PSObject.Properties[$PropertyName].Value
                }
            }
            @($AnalysisPatterns | Where-Object {
                $Pattern = $_
                @($GroupValues | Where-Object { $_ -like $Pattern }).Count -gt 0
            }).Count -gt 0
        })
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    Write-Verbose -Message ('Found {0} configured privileged group(s).' -f $Groups.Count)
    foreach ($Group in $Groups) {
        $GroupName = $null
        $GroupDn = $null
        $GroupSamAccountName = $null
        if ($null -ne $Group.PSObject.Properties['Name']) { $GroupName = [string]$Group.PSObject.Properties['Name'].Value }
        if ($null -ne $Group.PSObject.Properties['DistinguishedName']) { $GroupDn = [string]$Group.PSObject.Properties['DistinguishedName'].Value }
        if ($null -ne $Group.PSObject.Properties['SamAccountName']) { $GroupSamAccountName = [string]$Group.PSObject.Properties['SamAccountName'].Value }
        $GroupGuid = $null
        if ($null -ne $Group.PSObject.Properties['ObjectGUID']) { try { $GroupGuid = [guid]$Group.PSObject.Properties['ObjectGUID'].Value } catch { Write-Verbose -Message 'A group has an invalid ObjectGUID.' } }
        $GroupIsPrivileged = @($PrivilegePatterns | Where-Object { $GroupName -like $_ -or $GroupDn -like $_ }).Count -gt 0
        $Visited = @{}
        $Members = @(Resolve-TechHubADGroupMembership -GroupIdentity $GroupDn -VisitedGroups $Visited)

        if ($Members.Count -eq 0) {
            New-AssessmentADFinding `
                -AssessmentId $AssessmentId -CheckId $CheckId -CheckName $CheckName `
                -Category 'PrivilegedAccess' -Title ('Empty privileged group: {0}' -f $GroupName) `
                -Description 'The configured privileged group has no readable members.' -Severity 'Informational' `
                -Confidence 'Medium' -Status 'NotApplicable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $GroupName; ObjectClass = 'Group'; Enabled = $null }) `
                -ObjectType 'Group' -DistinguishedName $GroupDn -SamAccountName $GroupSamAccountName `
                -ObjectGuid $GroupGuid -Evidence ([PSCustomObject][ordered]@{ PrivilegedGroup = $GroupName; PrivilegedGroupDN = $GroupDn; MemberName = $null; MemberSamAccountName = $null; MemberObjectType = $null; MembershipType = $null; MembershipPath = @(); Enabled = $null; AdminCount = $null; PasswordNeverExpires = $null; Approved = $false; Excluded = $false }) `
                -Risk 'An empty privileged group is informational and should be reviewed for lifecycle and ownership.' `
                -Recommendation 'Confirm that the group is still required and has an owner; remove or archive it through a separately reviewed administrative process if appropriate.' `
                -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models') `
                -Domain $Domain -Forest $Forest -DomainController $DomainController
            continue
        }

        foreach ($Member in $Members) {
            if ($Member.Enabled -eq $false -and -not $IncludeDisabled) {
                Write-Verbose -Message ('Skipping disabled member {0}; use -IncludeDisabled to report it.' -f $Member.Name)
                continue
            }
            $IdentityValues = @($Member.Name, $Member.SamAccountName, $Member.DistinguishedName, $Member.SID) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            $Approved = @($ApprovedMemberPatterns | Where-Object { $Pattern = $_; @($IdentityValues | Where-Object { $_ -like $Pattern }).Count -gt 0 }).Count -gt 0
            $Excluded = @($ExcludedMemberPatterns | Where-Object { $Pattern = $_; @($IdentityValues | Where-Object { $_ -like $Pattern }).Count -gt 0 }).Count -gt 0
            $IsServiceAccount = $false
            if ($ServiceAccountPatterns.Count -gt 0) {
                $ServiceAccountValues = @($Member.Name, $Member.SamAccountName)
                $IsServiceAccount = @($ServiceAccountPatterns | Where-Object { $Pattern = $_; @($ServiceAccountValues | Where-Object { $_ -like $Pattern }).Count -gt 0 }).Count -gt 0
            }
            $Severity = 'Low'
            $Status = 'Finding'
            if ($Excluded -or $Approved) { $Severity = 'Informational'; $Status = 'NotApplicable' }
            elseif ($GroupIsPrivileged -and $Member.MembershipType -eq 'Indirect' -and $Member.ObjectClass -ne 'Group' -and $ApprovedMemberPatterns.Count -gt 0) { $Severity = 'Critical' }
            elseif ($GroupIsPrivileged -and ($IsServiceAccount -or ($Member.AdminCount -eq 1))) { $Severity = 'High' }
            elseif ($GroupIsPrivileged -and $ApprovedMemberPatterns.Count -gt 0) { $Severity = 'High' }
            elseif ($Member.Enabled -eq $false -or $Member.PasswordNeverExpires -eq $true -or ($Member.MembershipType -eq 'Indirect' -and $Member.ObjectClass -eq 'Group')) { $Severity = 'Medium' }
            elseif ($Member.MembershipType -eq 'Indirect' -and $Member.ObjectClass -eq 'Group') { $Severity = 'Medium' }
            $Evidence = [PSCustomObject][ordered]@{
                PrivilegedGroup = $GroupName; PrivilegedGroupDN = $GroupDn; MemberName = $Member.Name; MemberSamAccountName = $Member.SamAccountName; MemberObjectType = $Member.ObjectClass; MembershipType = $Member.MembershipType; MembershipPath = $Member.MembershipPath; Enabled = $Member.Enabled; AdminCount = $Member.AdminCount; PasswordNeverExpires = $Member.PasswordNeverExpires; Approved = $Approved; Excluded = $Excluded; IsServiceAccount = $IsServiceAccount; PrivilegedGroupMembership = @($GroupName)
            }
            New-AssessmentADFinding `
                -AssessmentId $AssessmentId -CheckId $CheckId -CheckName $CheckName -Category 'PrivilegedAccess' `
                -Title ('Privileged group membership: {0} in {1}' -f $Member.Name, $GroupName) `
                -Description 'The member is included in a configured privileged Active Directory group.' -Severity $Severity `
                -Confidence $(if ($Member.Resolved) { 'High' } else { 'Medium' }) -Status $Status `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Member.Name; ObjectClass = $Member.ObjectClass; Enabled = $Member.Enabled }) `
                -ObjectType $Member.ObjectClass -DistinguishedName $Member.DistinguishedName -SamAccountName $Member.SamAccountName `
                -ObjectGuid $Member.ObjectGUID -Evidence $Evidence `
                -Risk 'Privileged group membership increases the impact of compromise; the risk depends on authorization, scope, nesting, and account controls.' `
                -Recommendation 'Validate ownership and business need, apply least privilege, review nesting, and remove unneeded membership through a separately reviewed administrative process.' `
                -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models') `
                -Domain $Domain -Forest $Forest -DomainController $DomainController
        }
    }
}
