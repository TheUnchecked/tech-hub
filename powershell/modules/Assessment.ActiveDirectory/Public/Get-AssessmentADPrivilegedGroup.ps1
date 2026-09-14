#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADPrivilegedGroup {
    <#
    .SYNOPSIS
        Lists membership of privileged Active Directory groups.

    .DESCRIPTION
        Read-only, recursive membership listing of built-in privileged
        groups (Domain Admins, Enterprise Admins, Schema Admins,
        Administrators, Account Operators, Server Operators, Backup
        Operators, Domain Controllers) plus any extra group patterns
        supplied. Reports facts only; it does not compute a risk
        severity.

    .PARAMETER Server
        Optional domain controller.

    .PARAMETER SearchBase
        Optional Distinguished Name to limit the group search.

    .PARAMETER GroupPatterns
        Extra group name/DN wildcard patterns to include, on top of the
        built-in privileged groups.

    .PARAMETER IncludeDisabled
        Includes disabled members in the output. Excluded by default.

    .OUTPUTS
        GroupName, GroupDistinguishedName, MemberName, MemberSamAccountName,
        MemberObjectClass, MemberDistinguishedName, MembershipType
        (Direct/Indirect), MembershipPath, Enabled, AdminCount,
        PasswordNeverExpires, Domain
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$GroupPatterns = @(),

        [Parameter()]
        [switch]$IncludeDisabled
    )

    function Get-SafeMemberValue {
        param(
            [Parameter(Mandatory)]
            [object]$Member,

            [Parameter(Mandatory)]
            [string]$Name
        )

        if ($null -ne $Member.PSObject.Properties[$Name]) {
            return $Member.PSObject.Properties[$Name].Value
        }

        return $null
    }

    $DefaultGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Backup Operators', 'Domain Controllers')
    $AnalysisPatterns = @($DefaultGroups + $GroupPatterns)

    $GroupParameters = @{
        Filter      = '*'
        Properties  = @('Name', 'SamAccountName', 'DistinguishedName', 'ObjectGUID')
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $GroupParameters.Server = $Server
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $GroupParameters.SearchBase = $SearchBase
    }

    $Domain = $null

    try {
        $DomainContextParameters = @{ ErrorAction = 'Stop' }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $DomainContextParameters.Server = $Server
        }

        $Domain = (Get-ADDomain @DomainContextParameters).DNSRoot
    }
    catch {
        Write-Verbose -Message "Unable to resolve domain context: $($_.Exception.Message)"
    }

    try {
        $Groups = @(
            Get-ADGroup @GroupParameters | Where-Object {
                $Group = $_
                $GroupValues = @($Group.Name, $Group.SamAccountName, $Group.DistinguishedName)
                @($AnalysisPatterns | Where-Object { $Pattern = $_; @($GroupValues | Where-Object { $_ -like $Pattern }).Count -gt 0 }).Count -gt 0
            }
        )
    }
    catch {
        Write-Error -Message "Privileged group query failed: $($_.Exception.Message)"
        return
    }

    Write-Verbose -Message "Found $($Groups.Count) configured privileged group(s)."

    foreach ($Group in $Groups) {

        $Visited = @{}
        $Members = @(Resolve-AssessmentADGroupMembership -GroupIdentity $Group.DistinguishedName -VisitedGroups $Visited)

        foreach ($Member in $Members) {

            $MemberEnabled = Get-SafeMemberValue -Member $Member -Name 'Enabled'

            if ($MemberEnabled -eq $false -and -not $IncludeDisabled) {
                Write-Verbose -Message "Skipping disabled member $(Get-SafeMemberValue -Member $Member -Name 'Name'); use -IncludeDisabled to include it."
                continue
            }

            [PSCustomObject][ordered]@{
                GroupName              = $Group.Name
                GroupDistinguishedName = $Group.DistinguishedName
                MemberName             = Get-SafeMemberValue -Member $Member -Name 'Name'
                MemberSamAccountName   = Get-SafeMemberValue -Member $Member -Name 'SamAccountName'
                MemberObjectClass      = Get-SafeMemberValue -Member $Member -Name 'ObjectClass'
                MemberDistinguishedName = Get-SafeMemberValue -Member $Member -Name 'DistinguishedName'
                MembershipType         = Get-SafeMemberValue -Member $Member -Name 'MembershipType'
                MembershipPath         = Get-SafeMemberValue -Member $Member -Name 'MembershipPath'
                Enabled                = $MemberEnabled
                AdminCount             = Get-SafeMemberValue -Member $Member -Name 'AdminCount'
                PasswordNeverExpires   = Get-SafeMemberValue -Member $Member -Name 'PasswordNeverExpires'
                Domain                 = $Domain
                IsReadOnly             = $true
            }
        }
    }
}
