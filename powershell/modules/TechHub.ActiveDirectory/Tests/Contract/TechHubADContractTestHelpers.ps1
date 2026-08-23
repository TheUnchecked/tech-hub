function Get-TechHubADFindingContractProperties {
    @(
        'AssessmentId'
        'CheckId'
        'CheckName'
        'FindingId'
        'Title'
        'Description'
        'Category'
        'Severity'
        'Confidence'
        'Status'
        'AffectedObject'
        'ObjectType'
        'DistinguishedName'
        'SamAccountName'
        'ObjectGuid'
        'Evidence'
        'Risk'
        'Recommendation'
        'References'
        'CollectedAt'
        'IsReadOnly'
    )
}

function Assert-TechHubADFindingContract {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [string]$ExpectedCheckId,

        [Parameter(Mandatory)]
        [string]$ExpectedCheckName,

        [Parameter(Mandatory)]
        [string]$ExpectedCategory
    )

    $PropertyNames = @($Result.PSObject.Properties.Name)
    foreach ($PropertyName in (Get-TechHubADFindingContractProperties)) {
        $PropertyNames | Should -Contain $PropertyName
        $Property = $Result.PSObject.Properties[$PropertyName]
        $null -ne $Property.Value | Should -BeTrue -Because ("Contract property '{0}' must be populated." -f $PropertyName)
    }

    $Result.CheckId | Should -Be $ExpectedCheckId
    $Result.CheckName | Should -Be $ExpectedCheckName
    $Result.Category | Should -Be $ExpectedCategory
    $Result.IsReadOnly | Should -BeTrue
    $Result.FindingId | Should -Not -BeNullOrEmpty
    $Result.AssessmentId | Should -Not -BeNullOrEmpty
    $Result.CollectedAt | Should -Not -BeNullOrEmpty
}

function Assert-TechHubADSafeOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]$Results
    )

    foreach ($Result in $Results) {
        $Result -is [string] | Should -BeFalse
    }

    $SerializedResults = $Results | ConvertTo-Json -Depth 12
    $SerializedResults | Should -Not -Match '(?i)\b(password|secret|token|credential)\s*[:=]\s*[^,}\r\n]+'
    $PrivateKeyMarker = '-----' + 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    $SerializedResults | Should -Not -Match $PrivateKeyMarker
    $SerializedResults | Should -Not -Match '(?i)\b(bearer|basic)\s+[A-Za-z0-9+/=_-]{12,}'
    $SerializedResults | Should -Not -Match '^\s*\[[0-9]{4}-[0-9]{2}-[0-9]{2}[^\r\n]*\]\s+\[(INFO|WARNING|ERROR)\]'
}

function New-TechHubADContractDescriptor {
    param (
        [Parameter(Mandatory)]
        [string]$IdentityReference
    )

    $Rule = [PSCustomObject]@{
        IdentityReference = $IdentityReference
        AccessControlType = 'Allow'
        AccessMask        = 983551
        ObjectType        = [guid]::Empty
    }
    $Descriptor = [PSCustomObject]@{ AccessRules = @($Rule) }
    Add-Member -InputObject $Descriptor -MemberType ScriptMethod -Name GetAccessRules -Value { $this.AccessRules }
    $Descriptor
}
