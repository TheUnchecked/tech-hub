function Get-TechHubADRBCD {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$SensitiveTargetPatterns = @(),

        [Parameter()]
        [string[]]$ApprovedIdentityPatterns = @(),

        [Parameter()]
        [string[]]$ExcludedIdentityPatterns = @()
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-RBCD'
    $CheckName = 'Resource-Based Constrained Delegation'
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
        'msDS-AllowedToActOnBehalfOfOtherIdentity'
    )
    $QueryParameters = @{
        LDAPFilter  = '(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(|(objectCategory=computer)(objectCategory=person)(objectCategory=group)))'
        Properties  = $Properties
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $QueryParameters.Server = $Server
    }
    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $QueryParameters.SearchBase = $SearchBase
    }

    $Domain = $null
    $Forest = $null
    $DomainController = $Server
    try {
        $DomainParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $DomainParameters.Server = $Server
        }
        $DomainContext = Get-ADDomain @DomainParameters
        if ($null -ne $DomainContext) {
            $Domain = $DomainContext.DNSRoot
        }
    }
    catch {
        Write-Verbose -Message ('Unable to collect domain context: {0}' -f $_.Exception.Message)
    }
    try {
        $ForestParameters = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $ForestParameters.Server = $Server
        }
        $ForestContext = Get-ADForest @ForestParameters
        if ($null -ne $ForestContext) {
            $Forest = $ForestContext.Name
        }
    }
    catch {
        Write-Verbose -Message ('Unable to collect forest context: {0}' -f $_.Exception.Message)
    }

    try {
        Write-Verbose -Message 'Querying Active Directory for resource-based constrained delegation.'
        $Objects = @(Get-ADObject @QueryParameters)
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    Write-Verbose -Message ('Found {0} object(s) with RBCD configuration.' -f $Objects.Count)
    foreach ($Object in $Objects) {
        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = $null
        $ObjectType = 'Unknown'
        $ObjectClassValues = @()
        $TargetUac = $null
        $TargetEnabled = $null
        $Descriptor = $null

        if ($null -ne $Object.PSObject.Properties['Name']) {
            $Name = [string]$Object.PSObject.Properties['Name'].Value
        }
        if ($null -ne $Object.PSObject.Properties['DistinguishedName']) {
            $DistinguishedName = [string]$Object.PSObject.Properties['DistinguishedName'].Value
        }
        if ($null -ne $Object.PSObject.Properties['SamAccountName']) {
            $SamAccountName = [string]$Object.PSObject.Properties['SamAccountName'].Value
        }
        if ($null -ne $Object.PSObject.Properties['ObjectGUID']) {
            try { $ObjectGuid = [guid]$Object.PSObject.Properties['ObjectGUID'].Value } catch { Write-Verbose -Message 'An object has an invalid ObjectGUID value.' }
        }
        if ($null -ne $Object.PSObject.Properties['ObjectClass']) {
            $ObjectClassValues = @($Object.PSObject.Properties['ObjectClass'].Value)
        }
        if ($ObjectClassValues -contains 'computer') { $ObjectType = 'Computer' }
        elseif ($ObjectClassValues -contains 'user') { $ObjectType = 'User' }
        elseif ($ObjectClassValues -contains 'group') { $ObjectType = 'Group' }
        elseif ($null -ne $Object.PSObject.Properties['ObjectCategory'] -and [string]$Object.PSObject.Properties['ObjectCategory'].Value -match 'computer') { $ObjectType = 'Computer' }
        elseif ($null -ne $Object.PSObject.Properties['ObjectCategory'] -and [string]$Object.PSObject.Properties['ObjectCategory'].Value -match 'person') { $ObjectType = 'User' }
        elseif ($null -ne $Object.PSObject.Properties['ObjectCategory'] -and [string]$Object.PSObject.Properties['ObjectCategory'].Value -match 'group') { $ObjectType = 'Group' }
        if ($null -ne $Object.PSObject.Properties['UserAccountControl']) {
            try { $TargetUac = [int64]$Object.PSObject.Properties['UserAccountControl'].Value } catch { Write-Verbose -Message 'An object has an invalid UserAccountControl value.' }
        }
        if ($null -ne $Object.PSObject.Properties['Enabled'] -and $null -ne $Object.PSObject.Properties['Enabled'].Value) {
            $TargetEnabled = [bool]$Object.PSObject.Properties['Enabled'].Value
        }
        elseif ($null -ne $TargetUac) {
            $TargetEnabled = (($TargetUac -band [int64]0x2) -eq 0)
        }
        if ($null -ne $Object.PSObject.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity']) {
            $Descriptor = $Object.PSObject.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'].Value
        }
        if ($null -eq $Descriptor) {
            Write-Verbose -Message ('Skipping {0} because the RBCD descriptor is absent.' -f $Name)
            continue
        }

        $NormalizedTrustees = @()
        $DescriptorError = $null
        try {
            $NormalizedTrustees = @(ConvertFrom-TechHubADRBCDDescriptor -Descriptor $Descriptor)
        }
        catch {
            $DescriptorError = $_.Exception.Message
            Write-Verbose -Message ('Unable to read the RBCD descriptor for {0}: {1}' -f $Name, $DescriptorError)
        }

        $AuthorizedTrustees = @($NormalizedTrustees | Where-Object { $_.AccessType -eq 'Allow' })
        $ResolvedIdentities = @()
        $UnresolvedSids = @()
        foreach ($Trustee in $AuthorizedTrustees) {
            $Resolved = $null
            if (-not [string]::IsNullOrWhiteSpace($Trustee.SID)) {
                try {
                    $Resolved = Get-ADObject -Identity $Trustee.SID -Properties @('Name', 'ObjectClass', 'ObjectCategory', 'SamAccountName', 'DistinguishedName', 'ObjectGUID', 'Enabled', 'UserAccountControl') -ErrorAction Stop
                }
                catch {
                    Write-Verbose -Message ('Unable to resolve trustee SID {0}: {1}' -f $Trustee.SID, $_.Exception.Message)
                }
            }
            if ($null -ne $Resolved) {
                $ResolvedClass = 'Unknown'
                $ResolvedClasses = @($Resolved.ObjectClass)
                if ($ResolvedClasses -contains 'computer') { $ResolvedClass = 'Computer' }
                elseif ($ResolvedClasses -contains 'user') { $ResolvedClass = 'User' }
                elseif ($ResolvedClasses -contains 'group') { $ResolvedClass = 'Group' }
                $ResolvedIdentities += [PSCustomObject][ordered]@{
                    SID              = $Trustee.SID
                    Name             = $Resolved.Name
                    ObjectType       = $ResolvedClass
                    DistinguishedName = $Resolved.DistinguishedName
                    SamAccountName   = $Resolved.SamAccountName
                    ObjectGuid       = $Resolved.ObjectGUID
                    Enabled          = $Resolved.Enabled
                    UserAccountControl = $Resolved.UserAccountControl
                }
            }
            else {
                $UnresolvedSids += $Trustee.SID
            }
        }

        $AllowedIdentities = @($AuthorizedTrustees | ForEach-Object {
            [PSCustomObject][ordered]@{
                SID               = $_.SID
                IdentityReference = $_.IdentityReference
                AccessType        = $_.AccessType
                AccessMask        = $_.AccessMask
                ObjectType        = $_.ObjectType
            }
        })
        $TargetValues = @($Name, $DistinguishedName, $SamAccountName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $TargetSensitive = @($SensitiveTargetPatterns | Where-Object {
            $Pattern = $_
            @($TargetValues | Where-Object { $_ -like $Pattern }).Count -gt 0
        }).Count -gt 0
        $IdentityValues = @($AllowedIdentities | ForEach-Object { $_.SID; $_.IdentityReference })
        $IdentityValues += @($ResolvedIdentities | ForEach-Object { $_.SID; $_.Name; $_.SamAccountName; $_.DistinguishedName })
        $ApprovedMatches = @($IdentityValues | Where-Object {
            $Value = $_
            @($ApprovedIdentityPatterns | Where-Object { $Value -like $_ }).Count -gt 0
        } | Select-Object -Unique)
        $ExcludedMatches = @($IdentityValues | Where-Object {
            $Value = $_
            @($ExcludedIdentityPatterns | Where-Object { $Value -like $_ }).Count -gt 0
        } | Select-Object -Unique)
        $AllExcluded = $AllowedIdentities.Count -gt 0 -and $ExcludedMatches.Count -gt 0 -and
            @($AllowedIdentities | Where-Object { $ExcludedMatches -notcontains $_.SID }).Count -eq 0
        $HasBaseline = $ApprovedIdentityPatterns.Count -gt 0 -or $ExcludedIdentityPatterns.Count -gt 0
        $NonApprovedCount = @($AllowedIdentities | Where-Object { $ApprovedMatches -notcontains $_.SID }).Count

        $Severity = 'Low'
        $Status = 'Finding'
        if ($AllExcluded) {
            $Severity = 'Informational'
            $Status = 'NotApplicable'
        }
        elseif ($TargetSensitive -and $UnresolvedSids.Count -gt 0) { $Severity = 'Critical' }
        elseif ($TargetSensitive -and $AllowedIdentities.Count -gt 1 -and $NonApprovedCount -gt 0) { $Severity = 'Critical' }
        elseif ($UnresolvedSids.Count -gt 0 -or ($HasBaseline -and $NonApprovedCount -gt 0)) { $Severity = 'High' }
        elseif ($AllowedIdentities.Count -gt 1 -and (-not $HasBaseline)) { $Severity = 'Medium' }
        elseif ($AllowedIdentities.Count -gt 1 -and $NonApprovedCount -gt 0) { $Severity = 'Medium' }

        $Confidence = 'High'
        if ($null -ne $DescriptorError -or $UnresolvedSids.Count -gt 0 -or [string]::IsNullOrWhiteSpace($DistinguishedName)) { $Confidence = 'Medium' }
        $SecurityDescriptorPresent = $null -eq $DescriptorError
        $Evidence = [PSCustomObject][ordered]@{
            TargetObject             = $Name
            TargetObjectType         = $ObjectType
            AllowedIdentities        = $AllowedIdentities
            ResolvedIdentities       = $ResolvedIdentities
            UnresolvedSids            = $UnresolvedSids
            AccountEnabled            = $TargetEnabled
            SecurityDescriptorPresent = $SecurityDescriptorPresent
        }
        if ($null -ne $DescriptorError) {
            $Status = 'Error'
            $Severity = 'Medium'
        }
        New-TechHubADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Title ('Resource-based constrained delegation on {0}' -f $Name) `
            -Description 'The target has a security descriptor that authorizes one or more identities to act on its behalf.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status $Status `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Name; ObjectClass = $ObjectType; Enabled = $TargetEnabled }) `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk 'An unexpected identity authorized on a sensitive target can expand the impact of an account compromise.' `
            -Recommendation 'Review the business requirement, validate each trustee against an approved baseline, remove stale authorization through a separately reviewed administrative process, and retain only the minimum required identity.' `
            -References @('https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview') `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}
