#requires -Version 5.1

function Get-AssessmentADRBCD {
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

    # -------------------------------------------------------------------------
    # AD QUERY
    # -------------------------------------------------------------------------

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
        LDAPFilter  = '(&(msDS-AllowedToActOnBehalfOfOtherIdentity=\*)(|(objectCategory=computer)(objectCategory=person)(objectCategory=group)))'
        Properties  = $Properties
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $QueryParameters['Server'] = $Server
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $QueryParameters['SearchBase'] = $SearchBase
    }

    # -------------------------------------------------------------------------
    # AD CONTEXT
    # -------------------------------------------------------------------------

    $Domain = $null
    $Forest = $null
    $DomainController = $Server

    try {
        $ContextParameters = @{
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $ContextParameters['Server'] = $Server
        }

        $DomainContext = Get-ADDomain @ContextParameters

        if ($null -ne $DomainContext) {
            $Domain = [string]$DomainContext.DNSRoot
        }
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect domain context: {0}' -f
            $_.Exception.Message
        )
    }

    try {
        $ContextParameters = @{
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $ContextParameters['Server'] = $Server
        }

        $ForestContext = Get-ADForest @ContextParameters

        if ($null -ne $ForestContext) {
            $Forest = [string]$ForestContext.Name
        }
    }
    catch {
        Write-Verbose -Message (
            'Unable to collect forest context: {0}' -f
            $_.Exception.Message
        )
    }

    # -------------------------------------------------------------------------
    # DISCOVER RBCD TARGETS
    # -------------------------------------------------------------------------

    try {
        Write-Verbose -Message 'Querying Active Directory for RBCD targets.'

        $Objects = @(
            Get-ADObject @QueryParameters
        )
    }
    catch {
        Write-Error -ErrorRecord $_
        return
    }

    # -------------------------------------------------------------------------
    # PROCESS TARGETS
    # -------------------------------------------------------------------------

    foreach ($Object in $Objects) {

        $Name = $null
        $DistinguishedName = $null
        $SamAccountName = $null
        $ObjectGuid = [guid]::Empty
        $ObjectType = 'Unknown'
        $TargetEnabled = $null
        $Descriptor = $null

        # ---------------------------------------------------------------------
        # BASIC OBJECT PROPERTIES
        # ---------------------------------------------------------------------

        if ($null -ne $Object.PSObject.Properties['Name']) {
            $Name = [string]$Object.Name
        }

        if ($null -ne $Object.PSObject.Properties['DistinguishedName']) {
            $DistinguishedName = [string]$Object.DistinguishedName
        }

        if ($null -ne $Object.PSObject.Properties['SamAccountName']) {
            $SamAccountName = [string]$Object.SamAccountName
        }

        if ($null -ne $Object.PSObject.Properties['ObjectGUID']) {
            try {
                if ($null -ne $Object.ObjectGUID) {
                    $ObjectGuid = [guid]$Object.ObjectGUID
                }
            }
            catch {
                $ObjectGuid = [guid]::Empty
            }
        }

        # ---------------------------------------------------------------------
        # OBJECT TYPE
        # ---------------------------------------------------------------------

        $ObjectClasses = @()

        if ($null -ne $Object.PSObject.Properties['ObjectClass']) {
            $ObjectClasses = @($Object.ObjectClass)
        }

        if ($ObjectClasses -contains 'computer') {
            $ObjectType = 'Computer'
        }
        elseif ($ObjectClasses -contains 'user') {
            $ObjectType = 'User'
        }
        elseif ($ObjectClasses -contains 'group') {
            $ObjectType = 'Group'
        }
        elseif (
            $null -ne $Object.PSObject.Properties['ObjectCategory'] -and
            [string]$Object.ObjectCategory -match '(?i)computer'
        ) {
            $ObjectType = 'Computer'
        }
        elseif (
            $null -ne $Object.PSObject.Properties['ObjectCategory'] -and
            [string]$Object.ObjectCategory -match '(?i)person'
        ) {
            $ObjectType = 'User'
        }
        elseif (
            $null -ne $Object.PSObject.Properties['ObjectCategory'] -and
            [string]$Object.ObjectCategory -match '(?i)group'
        ) {
            $ObjectType = 'Group'
        }

        # ---------------------------------------------------------------------
        # ENABLED STATE
        # ---------------------------------------------------------------------

        if ($null -ne $Object.PSObject.Properties['Enabled']) {
            if ($null -ne $Object.Enabled) {
                $TargetEnabled = [bool]$Object.Enabled
            }
        }

        if ($null -eq $TargetEnabled) {
            if ($null -ne $Object.PSObject.Properties['UserAccountControl']) {
                try {
                    $TargetEnabled = (
                        ([int64]$Object.UserAccountControl -band 0x2) -eq 0
                    )
                }
                catch {
                    $TargetEnabled = $null
                }
            }
        }

        # ---------------------------------------------------------------------
        # RBCD SECURITY DESCRIPTOR
        # ---------------------------------------------------------------------

        if (
            $null -ne
            $Object.PSObject.Properties[
                'msDS-AllowedToActOnBehalfOfOtherIdentity'
            ]
        ) {
            $Descriptor =
                $Object.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        }

        if ($null -eq $Descriptor) {
            continue
        }

        $DescriptorError = $null
        $Rules = @()

        try {
            $Rules = @(
                ConvertFrom-AssessmentADRBCDDescriptor `
                    -Descriptor $Descriptor
            )
        }
        catch {
            $DescriptorError = $_.Exception.Message
        }

        # ---------------------------------------------------------------------
        # DESCRIPTOR ERROR
        # ---------------------------------------------------------------------

        if ($null -ne $DescriptorError) {

            $Evidence = [PSCustomObject][ordered]@{
                TargetObject              = $Name
                TargetObjectType          = $ObjectType
                AllowedIdentities         = @()
                ResolvedIdentities        = @()
                UnresolvedSids            = @()
                AccountEnabled            = $TargetEnabled
                SecurityDescriptorPresent = $false
                Error                     = $DescriptorError
            }

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'Delegation' `
                -Title ('Unable to read RBCD descriptor on {0}' -f $Name) `
                -Description 'The resource-based constrained delegation security descriptor could not be read.' `
                -Severity 'Medium' `
                -Confidence 'Medium' `
                -Status 'Error' `
                -AffectedObject (
                    [PSCustomObject][ordered]@{
                        Name        = $Name
                        ObjectClass = $ObjectType
                        Enabled     = $TargetEnabled
                    }
                ) `
                -ObjectType $ObjectType `
                -DistinguishedName $DistinguishedName `
                -SamAccountName $SamAccountName `
                -ObjectGuid $ObjectGuid `
                -Evidence $Evidence `
                -Risk 'The RBCD configuration could not be assessed reliably.' `
                -Recommendation 'Review the target security descriptor and repeat the assessment after the descriptor can be read.' `
                -References @(
                    'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
                ) `
                -Domain $Domain `
                -Forest $Forest `
                -DomainController $DomainController

            continue
        }

        # ---------------------------------------------------------------------
        # ALLOWED TRUSTEES
        # ---------------------------------------------------------------------

        $AllowedIdentities = @(
            $Rules |
                Where-Object {
                    $_.AccessType -eq 'Allow'
                }
        )

        $ResolvedIdentities =
            New-Object System.Collections.ArrayList

        $UnresolvedSids =
            New-Object System.Collections.ArrayList

        foreach ($Trustee in $AllowedIdentities) {

            $Sid = $null

            if (
                $null -ne $Trustee.PSObject.Properties['SID'] -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$Trustee.SID
                )
            ) {
                $Sid = [string]$Trustee.SID
            }

            if ([string]::IsNullOrWhiteSpace($Sid)) {
                continue
            }

            try {

                $TrusteeParameters = @{
                    Identity = $Sid
                    Properties = @(
                        'Name'
                        'ObjectClass'
                        'ObjectCategory'
                        'SamAccountName'
                        'DistinguishedName'
                        'ObjectGUID'
                        'Enabled'
                        'UserAccountControl'
                    )
                    ErrorAction = 'Stop'
                }

                if (-not [string]::IsNullOrWhiteSpace($Server)) {
                    $TrusteeParameters['Server'] = $Server
                }

                $Resolved = Get-ADObject @TrusteeParameters

                if ($null -eq $Resolved) {
                    throw 'Identity was not resolved.'
                }

                # -------------------------------------------------------------
                # TRUSTEE TYPE
                # -------------------------------------------------------------

                $ResolvedObjectType = 'Unknown'

                $ResolvedClasses = @(
                    $Resolved.ObjectClass
                )

                if ($ResolvedClasses -contains 'computer') {
                    $ResolvedObjectType = 'Computer'
                }
                elseif ($ResolvedClasses -contains 'user') {
                    $ResolvedObjectType = 'User'
                }
                elseif ($ResolvedClasses -contains 'group') {
                    $ResolvedObjectType = 'Group'
                }
                elseif (
                    $null -ne
                    $Resolved.PSObject.Properties['ObjectCategory']
                ) {

                    $Category =
                        [string]$Resolved.ObjectCategory

                    if ($Category -match '(?i)computer') {
                        $ResolvedObjectType = 'Computer'
                    }
                    elseif ($Category -match '(?i)person') {
                        $ResolvedObjectType = 'User'
                    }
                    elseif ($Category -match '(?i)group') {
                        $ResolvedObjectType = 'Group'
                    }
                }

                [void]$ResolvedIdentities.Add(
                    [PSCustomObject][ordered]@{
                        SID                = $Sid
                        Name               = $Resolved.Name
                        ObjectType         = $ResolvedObjectType
                        DistinguishedName  = $Resolved.DistinguishedName
                        SamAccountName     = $Resolved.SamAccountName
                        ObjectGuid         = $Resolved.ObjectGUID
                        Enabled            = $Resolved.Enabled
                        UserAccountControl = $Resolved.UserAccountControl
                    }
                )
            }
            catch {

                [void]$UnresolvedSids.Add($Sid)

                Write-Verbose -Message (
                    'Unable to resolve trustee SID {0}: {1}' -f
                    $Sid,
                    $_.Exception.Message
                )
            }
        }

        # ---------------------------------------------------------------------
        # SENSITIVE TARGET MATCH
        # ---------------------------------------------------------------------

        $TargetValues = @(
            $Name
            $DistinguishedName
            $SamAccountName
        ) |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            }

        $SensitiveMatch = $false

        foreach ($Pattern in $SensitiveTargetPatterns) {

            foreach ($Value in $TargetValues) {

                if ($Value -like $Pattern) {
                    $SensitiveMatch = $true
                    break
                }
            }

            if ($SensitiveMatch) {
                break
            }
        }

        # ---------------------------------------------------------------------
        # IDENTITY BASELINES
        # ---------------------------------------------------------------------

        $IdentityValues = @()

        foreach ($Identity in $AllowedIdentities) {

            if ($null -ne $Identity.SID) {
                $IdentityValues += [string]$Identity.SID
            }

            if ($null -ne $Identity.IdentityReference) {
                $IdentityValues += [string]$Identity.IdentityReference
            }
        }

        foreach ($Identity in $ResolvedIdentities) {

            if ($null -ne $Identity.SID) {
                $IdentityValues += [string]$Identity.SID
            }

            if ($null -ne $Identity.Name) {
                $IdentityValues += [string]$Identity.Name
            }

            if ($null -ne $Identity.SamAccountName) {
                $IdentityValues += [string]$Identity.SamAccountName
            }

            if ($null -ne $Identity.DistinguishedName) {
                $IdentityValues += [string]$Identity.DistinguishedName
            }
        }

        $Approved = $false
        $Excluded = $false

        foreach ($Pattern in $ApprovedIdentityPatterns) {

            foreach ($Value in $IdentityValues) {

                if (
                    -not [string]::IsNullOrWhiteSpace([string]$Value) -and
                    $Value -like $Pattern
                ) {
                    $Approved = $true
                    break
                }
            }

            if ($Approved) {
                break
            }
        }

        foreach ($Pattern in $ExcludedIdentityPatterns) {

            foreach ($Value in $IdentityValues) {

                if (
                    -not [string]::IsNullOrWhiteSpace([string]$Value) -and
                    $Value -like $Pattern
                ) {
                    $Excluded = $true
                    break
                }
            }

            if ($Excluded) {
                break
            }
        }

        # ---------------------------------------------------------------------
        # SEVERITY
        # ---------------------------------------------------------------------

        $Severity = 'Low'
        $Status = 'Finding'

        if ($Excluded) {
            $Severity = 'Informational'
            $Status = 'NotApplicable'
        }
        elseif (
            $SensitiveMatch -and
            $UnresolvedSids.Count -gt 0
        ) {
            $Severity = 'Critical'
        }
        elseif ($Approved) {
            $Severity = 'Low'
        }
        elseif ($UnresolvedSids.Count -gt 0) {
            $Severity = 'High'
        }
        elseif ($AllowedIdentities.Count -gt 1) {
            $Severity = 'Medium'
        }

        $Confidence = 'High'

        if ($UnresolvedSids.Count -gt 0) {
            $Confidence = 'Medium'
        }

        # ---------------------------------------------------------------------
        # EVIDENCE
        # ---------------------------------------------------------------------

        $Evidence = [PSCustomObject][ordered]@{
            TargetObject              = $Name
            TargetObjectType          = $ObjectType
            AllowedIdentities         = @($AllowedIdentities)
            ResolvedIdentities        = @($ResolvedIdentities)
            UnresolvedSids            = @($UnresolvedSids)
            AccountEnabled            = $TargetEnabled
            SecurityDescriptorPresent = $true
        }

        # ---------------------------------------------------------------------
        # FINDING
        # ---------------------------------------------------------------------

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'Delegation' `
            -Title ('Resource-based constrained delegation on {0}' -f $Name) `
            -Description 'The target has a security descriptor authorizing one or more identities to act on its behalf.' `
            -Severity $Severity `
            -Confidence $Confidence `
            -Status $Status `
            -AffectedObject (
                [PSCustomObject][ordered]@{
                    Name        = $Name
                    ObjectClass = $ObjectType
                    Enabled     = $TargetEnabled
                }
            ) `
            -ObjectType $ObjectType `
            -DistinguishedName $DistinguishedName `
            -SamAccountName $SamAccountName `
            -ObjectGuid $ObjectGuid `
            -Evidence $Evidence `
            -Risk 'Unexpected RBCD authorization can increase the impact of a compromised identity.' `
            -Recommendation 'Validate each authorized identity against the organization baseline and remove unauthorized delegation through a separately reviewed administrative process.' `
            -References @(
                'https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
            ) `
            -Domain $Domain `
            -Forest $Forest `
            -DomainController $DomainController
    }
}