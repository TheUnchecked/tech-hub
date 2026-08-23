function New-TechHubADAssessmentResult {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Guid]$AssessmentId,

        [Parameter()]
        [Nullable[datetime]]$StartedAt,

        [Parameter()]
        [Nullable[datetime]]$CompletedAt,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Forest,

        [Parameter()]
        [string]$DomainController,

        [Parameter()]
        [ValidateSet('Finding', 'Observation', 'Inventory', 'Health')]
        [string]$ResultType,

        [Parameter()]
        [ValidateSet('Available', 'Partial', 'NotAvailable', 'Error')]
        [string]$ProviderStatus,

        [Parameter()]
        [ValidateSet('Complete', 'Partial', 'NotAvailable')]
        [string]$DataAvailability
    )

    $Result = [TechHubADAssessmentResult]::new()
    if ($AssessmentId -ne [guid]::Empty) { $Result.AssessmentId = $AssessmentId }
    if ($PSBoundParameters.ContainsKey('StartedAt')) { $Result.StartedAt = $StartedAt.Value.ToUniversalTime() }
    if ($PSBoundParameters.ContainsKey('CompletedAt')) { $Result.Complete($CompletedAt.Value) }
    if ($PSBoundParameters.ContainsKey('Domain')) { $Result.Domain = $Domain }
    if ($PSBoundParameters.ContainsKey('Forest')) { $Result.Forest = $Forest }
    if ($PSBoundParameters.ContainsKey('DomainController')) { $Result.DomainController = $DomainController }
    if ($PSBoundParameters.ContainsKey('ResultType')) { $Result.ResultType = $ResultType }
    if ($PSBoundParameters.ContainsKey('ProviderStatus')) { $Result.SetProviderStatus($ProviderStatus) }
    if ($PSBoundParameters.ContainsKey('DataAvailability')) { $Result.SetDataAvailability($DataAvailability) }
    $Result
}
