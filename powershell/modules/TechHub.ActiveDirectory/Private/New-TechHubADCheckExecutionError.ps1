function New-AssessmentADCheckExecutionError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Definition,

        [Parameter(Mandatory)]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$ErrorType,

        [Parameter(Mandatory)]
        [string]$ErrorMessage,

        [Parameter(Mandatory)]
        [datetime]$StartedAt,

        [Parameter(Mandatory)]
        [datetime]$CompletedAt
    )

    [PSCustomObject][ordered]@{
        CheckId       = [string]$Definition.CheckId
        CheckName     = [string]$Definition.Name
        Status        = $Status
        ErrorType     = $ErrorType
        ErrorMessage  = $ErrorMessage
        StartedAt     = $StartedAt.ToUniversalTime()
        CompletedAt   = $CompletedAt.ToUniversalTime()
        Duration      = $CompletedAt.ToUniversalTime() - $StartedAt.ToUniversalTime()
        IsReadOnly    = $true
    }
}
