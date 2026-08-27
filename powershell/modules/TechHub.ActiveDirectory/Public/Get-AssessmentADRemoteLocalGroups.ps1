#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteLocalGroups {

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'Computer',
            'CN',
            'Host',
            'Name',
            'DNSHostName'
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        $AssessmentId = [guid]::NewGuid()
        $CheckId = 'AD-REMOTE-LOCAL-GROUPS'
        $CheckName = 'Remote Local Group Membership'

        foreach ($Computer in $ComputerName) {

            Write-Verbose "Assessing remote local groups on [$Computer]."

            # ========================================================
            # COLLECTOR
            # ========================================================

            try {

                $CollectorParameters = @{
                    ComputerName = $Computer
                    ErrorAction  = 'Stop'
                }

                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $CollectorParameters.Credential = $Credential
                }

                $Groups = @(
                    Get-AssessmentADRemoteLocalGroupMembers @CollectorParameters
                )
            }
            catch {

                $Evidence = [PSCustomObject][ordered]@{
                    ComputerName     = $Computer
                    CollectionMethod = 'WMI'
                    Transport        = 'None'
                    Status           = 'NotAvailable'
                    DataAvailability = 'NotAvailable'
                    ErrorType        = 'RemoteLocalGroupCollectionError'
                    ErrorMessage     = $_.Exception.Message
                    IsReadOnly       = $true
                }

                New-AssessmentADFinding `
                    -AssessmentId $AssessmentId `
                    -CheckId $CheckId `
                    -CheckName $CheckName `
                    -Category 'PrivilegedAccess' `
                    -Title "Unable to assess local groups on $Computer" `
                    -Description 'The remote local group membership assessment could not collect data from the target computer.' `
                    -Severity 'Medium' `
                    -Confidence 'High' `
                    -Status 'Error' `
                    -AffectedObject (
                        [PSCustomObject][ordered]@{
                            ComputerName = $Computer
                            ObjectType   = 'Computer'
                        }
                    ) `
                    -ObjectType 'Computer' `
                    -DistinguishedName $null `
                    -SamAccountName $null `
                    -ObjectGuid $null `
                    -Evidence $Evidence `
                    -Risk 'Unable to verify local group membership on the target computer.' `
                    -Recommendation 'Verify read-only remote management connectivity and repeat the assessment.' `
                    -References @(
                        'https://learn.microsoft.com/windows/win32/cimwin32prov/win32-group'
                    )

                continue
            }

            # ========================================================
            # GROUPS
            # ========================================================

            foreach ($GroupResult in $Groups) {

                if ($null -eq $GroupResult) {
                    continue
                }

                $GroupName = [string]$GroupResult.GroupName

                $Members = @()

                if (
                    $GroupResult.PSObject.Properties['GroupMembers'] -and
                    $null -ne $GroupResult.GroupMembers
                ) {
                    $Members = @($GroupResult.GroupMembers)
                }

                # ====================================================
                # COLLECTION FAILURE
                # ====================================================

                if (
                    $GroupResult.PSObject.Properties['Status'] -and
                    [string]$GroupResult.Status -eq 'NotAvailable'
                ) {

                    $Evidence = [PSCustomObject][ordered]@{
                        ComputerName     = $Computer
                        GroupName        = $GroupName
                        CollectionMethod = $GroupResult.CollectionMethod
                        Transport        = $GroupResult.Transport
                        Status           = $GroupResult.Status
                        DataAvailability = $GroupResult.DataAvailability
                        ErrorType        = $GroupResult.ErrorType
                        ErrorMessage     = $GroupResult.ErrorMessage
                    }

                    New-AssessmentADFinding `
                        -AssessmentId $AssessmentId `
                        -CheckId $CheckId `
                        -CheckName $CheckName `
                        -Category 'PrivilegedAccess' `
                        -Title "Unable to collect local group $GroupName on $Computer" `
                        -Description 'The local group could not be assessed because membership data was not available.' `
                        -Severity 'Medium' `
                        -Confidence 'High' `
                        -Status 'Error' `
                        -AffectedObject (
                            [PSCustomObject][ordered]@{
                                ComputerName = $Computer
                                GroupName    = $GroupName
                                ObjectType   = 'LocalGroup'
                            }
                        ) `
                        -ObjectType 'LocalGroup' `
                        -DistinguishedName $null `
                        -SamAccountName $null `
                        -ObjectGuid $null `
                        -Evidence $Evidence `
                        -Risk 'Unverified local group membership can hide unauthorized or excessive local access.' `
                        -Recommendation 'Restore read-only remote collection capability and repeat the assessment.' `
                        -References @(
                            'https://learn.microsoft.com/windows/win32/cimwin32prov/win32-group'
                        )

                    continue
                }

                # ====================================================
                # EMPTY GROUP
                # ====================================================

                if ($Members.Count -eq 0) {

                    $Evidence = [PSCustomObject][ordered]@{
                        ComputerName = $Computer
                        GroupName    = $GroupName
                        MemberCount  = 0
                    }

                    New-AssessmentADFinding `
                        -AssessmentId $AssessmentId `
                        -CheckId $CheckId `
                        -CheckName $CheckName `
                        -Category 'PrivilegedAccess' `
                        -Title "Empty local group: $GroupName on $Computer" `
                        -Description 'The local group contains no readable members.' `
                        -Severity 'Informational' `
                        -Confidence 'High' `
                        -Status 'NotApplicable' `
                        -AffectedObject (
                            [PSCustomObject][ordered]@{
                                ComputerName = $Computer
                                GroupName    = $GroupName
                                ObjectType   = 'LocalGroup'
                            }
                        ) `
                        -ObjectType 'LocalGroup' `
                        -DistinguishedName $null `
                        -SamAccountName $null `
                        -ObjectGuid $null `
                        -Evidence $Evidence `
                        -Risk 'An empty local group is informational and should be reviewed for lifecycle and ownership.' `
                        -Recommendation 'Confirm that the local group is still required and remove unused groups through a separately reviewed administrative process.' `
                        -References @(
                            'https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts'
                        )

                    continue
                }

                # ====================================================
                # MEMBERS
                # ====================================================

                foreach ($MemberObject in $Members) {

                    if ($null -eq $MemberObject) {
                        continue
                    }

                    # ------------------------------------------------
                    # MEMBER NAME
                    # ------------------------------------------------

                    $Member = $null

                    if (
                        $MemberObject.PSObject.Properties['Member'] -and
                        $null -ne $MemberObject.Member
                    ) {

                        $Member = [string]$MemberObject.Member
                    }
                    else {

                        $Domain = $null
                        $Name = $null

                        if ($MemberObject.PSObject.Properties['Domain']) {
                            $Domain = [string]$MemberObject.Domain
                        }

                        if ($MemberObject.PSObject.Properties['Name']) {
                            $Name = [string]$MemberObject.Name
                        }

                        if (
                            -not [string]::IsNullOrWhiteSpace($Domain) -and
                            -not [string]::IsNullOrWhiteSpace($Name)
                        ) {
                            $Member = "$Domain\$Name"
                        }
                        elseif (
                            -not [string]::IsNullOrWhiteSpace($Name)
                        ) {
                            $Member = $Name
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($Member)) {
                        continue
                    }

                    # ------------------------------------------------
                    # MEMBER ATTRIBUTES
                    # ------------------------------------------------

                    $SID = $null

                    if ($MemberObject.PSObject.Properties['SID']) {
                        $SID = [string]$MemberObject.SID
                    }

                    $LocalAccount = $false

                    if (
                        $MemberObject.PSObject.Properties['LocalAccount'] -and
                        $null -ne $MemberObject.LocalAccount
                    ) {
                        $LocalAccount = [bool]$MemberObject.LocalAccount
                    }

                    # ------------------------------------------------
                    # CLASSIFICATION
                    # ------------------------------------------------

                    $MemberType = $null

                    if (
                        $MemberObject.PSObject.Properties['MemberType'] -and
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$MemberObject.MemberType
                        )
                    ) {

                        $MemberType = [string]$MemberObject.MemberType
                    }
                    else {

                        $MemberType =
                            Get-TechHubADRemoteLocalGroupMemberClassification `
                                -ComputerName $Computer `
                                -GroupName $GroupName `
                                -Member $Member `
                                -SID $SID `
                                -LocalAccount $LocalAccount
                    }

                    # ------------------------------------------------
                    # DEFAULT SEVERITY
                    # ------------------------------------------------

                    $Severity = 'Low'
                    $Status = 'Finding'
                    $Confidence = 'High'

                    if ($MemberType -eq 'LocalAccount') {

                        $Severity = 'Medium'
                    }
                    elseif ($MemberType -eq 'DomainPrincipal') {

                        $Severity = 'Medium'
                    }
                    elseif ($MemberType -eq 'BuiltInPrincipal') {

                        $Severity = 'Informational'
                        $Status = 'NotApplicable'
                    }
                    elseif ($MemberType -eq 'WellKnownPrincipal') {

                        $Severity = 'Informational'
                        $Status = 'NotApplicable'
                    }
                    else {

                        $Severity = 'Low'
                        $Confidence = 'Medium'
                    }

                    # ------------------------------------------------
                    # ADMINISTRATORS
                    # ------------------------------------------------

                    if (
                        $GroupName -ieq 'Administrators' -and
                        $MemberType -eq 'LocalAccount'
                    ) {

                        $Severity = 'High'
                        $Status = 'Finding'
                    }

                    if (
                        $GroupName -ieq 'Administrators' -and
                        $MemberType -eq 'DomainPrincipal'
                    ) {

                        $Severity = 'High'
                        $Status = 'Finding'
                    }

                    # ------------------------------------------------
                    # DOMAIN / NAME
                    # ------------------------------------------------

                    $Domain = $null

                    if ($MemberObject.PSObject.Properties['Domain']) {
                        $Domain = [string]$MemberObject.Domain
                    }

                    $Name = $null

                    if ($MemberObject.PSObject.Properties['Name']) {
                        $Name = [string]$MemberObject.Name
                    }

                    $AccountType = $null

                    if ($MemberObject.PSObject.Properties['AccountType']) {
                        $AccountType = $MemberObject.AccountType
                    }

                    # ------------------------------------------------
                    # COLLECTION INFORMATION
                    # ------------------------------------------------

                    $CollectionMethod = $null

                    if (
                        $GroupResult.PSObject.Properties['CollectionMethod']
                    ) {
                        $CollectionMethod =
                            [string]$GroupResult.CollectionMethod
                    }

                    $Transport = $null

                    if (
                        $GroupResult.PSObject.Properties['Transport']
                    ) {
                        $Transport =
                            [string]$GroupResult.Transport
                    }

                    $GroupStatus = $null

                    if (
                        $GroupResult.PSObject.Properties['Status']
                    ) {
                        $GroupStatus =
                            [string]$GroupResult.Status
                    }

                    $DataAvailability = $null

                    if (
                        $GroupResult.PSObject.Properties['DataAvailability']
                    ) {
                        $DataAvailability =
                            [string]$GroupResult.DataAvailability
                    }

                    # ------------------------------------------------
                    # TARGET TYPE
                    # ------------------------------------------------

                    $TargetType = 'Unknown'

                    if (
                        $GroupResult.PSObject.Properties['TargetType'] -and
                        $null -ne $GroupResult.TargetType
                    ) {
                        $TargetType = [string]$GroupResult.TargetType
                    }

                    # ------------------------------------------------
                    # EVIDENCE
                    # ------------------------------------------------

                    $Evidence = [PSCustomObject][ordered]@{

                        ComputerName = $Computer
                        TargetType = $TargetType
                        GroupName = $GroupName

                        Member = $Member
                        MemberType = $MemberType

                        Domain = $Domain
                        Name = $Name
                        SID = $SID

                        LocalAccount = $LocalAccount
                        AccountType = $AccountType

                        CollectionMethod = $CollectionMethod
                        Transport = $Transport
                        Status = $GroupStatus
                        DataAvailability = $DataAvailability

                        IsReadOnly = $true
                    }

                    # ------------------------------------------------
                    # RISK
                    # ------------------------------------------------

                    if ($GroupName -ieq 'Administrators') {

                        $Risk =
                            'Membership in the local Administrators group grants extensive administrative privileges on the target computer.'
                    }
                    elseif ($MemberType -eq 'LocalAccount') {

                        $Risk =
                            'Local account membership can provide persistent access to the target computer and should be reviewed against least-privilege requirements.'
                    }
                    elseif ($MemberType -eq 'DomainPrincipal') {

                        $Risk =
                            'Domain principal membership creates a path from Active Directory identities to local access on the target computer.'
                    }
                    else {

                        $Risk =
                            'Local group membership should be reviewed to confirm that the resulting access is expected.'
                    }

                    # ------------------------------------------------
                    # RECOMMENDATION
                    # ------------------------------------------------

                    if ($GroupName -ieq 'Administrators') {

                        $Recommendation =
                            'Validate membership against the administrative model, remove unnecessary principals, and prefer controlled administrative groups and just-in-time access where available.'
                    }
                    else {

                        $Recommendation =
                            'Validate the membership against the intended access model and remove unnecessary principals through a separately reviewed administrative process.'
                    }

                    # ------------------------------------------------
                    # FINDING
                    # ------------------------------------------------

                    New-AssessmentADFinding `
                        -AssessmentId $AssessmentId `
                        -CheckId $CheckId `
                        -CheckName $CheckName `
                        -Category 'PrivilegedAccess' `
                        -Title (
                            "Local group membership: $Member in $GroupName on $Computer"
                        ) `
                        -Description (
                            'A security principal was identified as a member of a local Windows group on a remote computer.'
                        ) `
                        -Severity $Severity `
                        -Confidence $Confidence `
                        -Status $Status `
                        -AffectedObject (
                            [PSCustomObject][ordered]@{
                                ComputerName = $Computer
                                GroupName    = $GroupName
                                Member       = $Member
                                MemberType   = $MemberType
                            }
                        ) `
                        -ObjectType 'LocalGroupMember' `
                        -DistinguishedName $null `
                        -SamAccountName $null `
                        -ObjectGuid $null `
                        -Evidence $Evidence `
                        -Risk $Risk `
                        -Recommendation $Recommendation `
                        -References @(
                            'https://learn.microsoft.com/windows/security/identity-protection/access-control/local-accounts'
                        )
                }
            }
        }
    }
}