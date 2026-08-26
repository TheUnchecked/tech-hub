function New-AssessmentADFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Guid]$AssessmentId,

        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$Category = 'Delegation',

        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Confidence,

        [Parameter(Mandatory)]
        [string]$Status,

        [Parameter(Mandatory)]
        [object]$AffectedObject,

        [Parameter(Mandatory)]
        [string]$ObjectType,

        [AllowNull()]
        [string]$DistinguishedName,

        [AllowNull()]
        [string]$SamAccountName,

        [AllowNull()]
        [Nullable[Guid]]$ObjectGuid,

        [Parameter(Mandatory)]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [string]$Risk,

        [Parameter(Mandatory)]
        [string]$Recommendation,

        [Parameter(Mandatory)]
        [string[]]$References,

        [AllowNull()]
        [string]$Domain,

        [AllowNull()]
        [string]$Forest,

        [AllowNull()]
        [string]$DomainController
    )

    [PSCustomObject][ordered]@{
        AssessmentId      = $AssessmentId
        CheckId           = $CheckId
        CheckName         = $CheckName
        FindingId         = ([guid]::NewGuid()).Guid
        Title             = $Title
        Description       = $Description
        Category          = $Category
        Severity          = $Severity
        Confidence        = $Confidence
        Status            = $Status
        AffectedObject    = $AffectedObject
        ObjectType        = $ObjectType
        DistinguishedName = $DistinguishedName
        SamAccountName    = $SamAccountName
        ObjectGuid        = $ObjectGuid
        Evidence          = $Evidence
        Risk              = $Risk
        Recommendation    = $Recommendation
        References        = $References
        CollectedAt       = (Get-Date).ToUniversalTime()
        Domain            = $Domain
        Forest            = $Forest
        DomainController  = $DomainController
        IsReadOnly        = $true
    }
}