#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteAuditPolicy {
    <#
    .SYNOPSIS
        Evaluates whether security-relevant audit subcategories are enabled
        on remote Windows computers, returning one security finding per
        computer.

    .DESCRIPTION
        Read-only remote assessment. Runs the built-in, read-only
        'auditpol /get' command over WinRM (Invoke-Command) and checks
        whether a configurable set of security-relevant subcategories has
        any auditing enabled at all. It does not evaluate whether each
        subcategory is set to Success, Failure, or both, since the
        recommended setting differs per subcategory; it only flags
        subcategories left at "No Auditing".

        When -ComputerName is not supplied, targets are discovered with
        Get-AssessmentADRemoteTargets (default -TargetType DomainController,
        since the default subcategory list is Directory-Service and
        Kerberos focused).

    .PARAMETER ComputerName
        Explicit list of computers to assess. Bypasses automatic discovery.

    .PARAMETER TargetType
        Discovery scope used when -ComputerName is not supplied. Defaults
        to 'DomainController'.

    .PARAMETER AuditedSubcategories
        Advanced Audit Policy subcategory names expected to have some
        auditing enabled. Subcategories not present in the remote
        auditpol output (for example, Directory Service subcategories on
        a non-domain-controller) are silently skipped rather than flagged.

    .PARAMETER Credential
        Optional alternate credential for the remote WinRM session.

    .PARAMETER Server
        Domain controller used to build a provider for target discovery,
        when -Provider is not supplied.

    .PARAMETER Provider
        Optional pre-built TechHubADProvider, used for target discovery.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$TargetType = 'DomainController',

        [Parameter()]
        [string[]]$AuditedSubcategories = @(
            'Directory Service Access'
            'Directory Service Changes'
            'Kerberos Authentication Service'
            'Kerberos Service Ticket Operations'
            'Credential Validation'
            'Logon'
            'Logoff'
        ),

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [object]$Provider
    )

    $AssessmentId = [guid]::NewGuid()
    $CheckId = 'AD-AUDIT-POLICY'
    $CheckName = 'Advanced Audit Policy Coverage'
    $HighImpactSubcategories = @(
        'Directory Service Access'
        'Directory Service Changes'
        'Kerberos Authentication Service'
        'Kerberos Service Ticket Operations'
    )

    $Targets = @()

    if ($PSBoundParameters.ContainsKey('ComputerName')) {

        $Targets = @(
            $ComputerName |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
    else {

        if ($null -eq $Provider) {
            $Provider = New-AssessmentADProvider -Server $Server
        }

        try {
            Write-Verbose -Message ('Discovering remote targets (TargetType = {0}).' -f $TargetType)

            $Targets = @(
                Get-AssessmentADRemoteTargets -Provider $Provider -TargetType $TargetType |
                    ForEach-Object { [string]$_.ComputerName } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        catch {
            Write-Error -ErrorRecord $_
            return
        }
    }

    if ($Targets.Count -eq 0) {
        Write-Verbose -Message 'No targets were supplied or discovered; nothing to assess.'
        return
    }

    foreach ($Target in $Targets) {

        Write-Verbose -Message "[$Target] Collecting Advanced Audit Policy configuration."

        try {

            $InvokeParams = @{
                ComputerName = $Target
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    auditpol /get /category:* /r |
                        ConvertFrom-Csv
                }
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $InvokeParams.Credential = $Credential
            }

            $AuditRows = @(Invoke-Command @InvokeParams)
        }
        catch {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'AuditingAndLogging' `
                -Title ('Audit policy assessment unavailable for {0}' -f $Target) `
                -Description 'The remote audit policy could not be read (auditpol over WinRM).' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ErrorType = 'RemoteQueryError'; ErrorMessage = $_.Exception.Message }) `
                -Risk 'No security conclusion can be made because the remote audit policy was unavailable.' `
                -Recommendation 'Verify WinRM connectivity to the target and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations') `
                -Domain $null `
                -Forest $null `
                -DomainController $null

            continue
        }

        if ($AuditRows.Count -eq 0) {

            New-AssessmentADFinding `
                -AssessmentId $AssessmentId `
                -CheckId $CheckId `
                -CheckName $CheckName `
                -Category 'AuditingAndLogging' `
                -Title ('Audit policy assessment unavailable for {0}' -f $Target) `
                -Description 'auditpol returned no data.' `
                -Severity 'Informational' `
                -Confidence 'High' `
                -Status 'NotAvailable' `
                -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
                -ObjectType 'Computer' `
                -DistinguishedName $null `
                -SamAccountName $null `
                -ObjectGuid ([guid]::Empty) `
                -Evidence ([PSCustomObject][ordered]@{ ErrorType = 'NoData'; ErrorMessage = 'auditpol returned no rows.' }) `
                -Risk 'No security conclusion can be made because the remote audit policy was unavailable.' `
                -Recommendation 'Verify WinRM connectivity to the target and rerun the assessment.' `
                -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations') `
                -Domain $null `
                -Forest $null `
                -DomainController $null

            continue
        }

        $NotAudited = @()
        $Evaluated = @()

        foreach ($SubcategoryName in $AuditedSubcategories) {

            $Row = @($AuditRows) |
                Where-Object { [string]$_.Subcategory -eq $SubcategoryName } |
                Select-Object -First 1

            if ($null -eq $Row) {
                # Not present on this computer (for example, Directory
                # Service subcategories on a non-domain-controller) -
                # nothing to evaluate.
                continue
            }

            $Evaluated += $SubcategoryName

            $InclusionSetting = $null

            if ($null -ne $Row.PSObject.Properties['Inclusion Setting']) {
                $InclusionSetting = [string]$Row.PSObject.Properties['Inclusion Setting'].Value
            }

            if ($InclusionSetting -eq 'No Auditing') {
                $NotAudited += $SubcategoryName
            }
        }

        $Severity = 'Informational'

        if (@($NotAudited | Where-Object { $HighImpactSubcategories -contains $_ }).Count -gt 0) {
            $Severity = 'High'
        }
        elseif ($NotAudited.Count -gt 0) {
            $Severity = 'Medium'
        }

        $Risk = 'The evaluated audit subcategories all have some level of auditing enabled.'

        if ($NotAudited.Count -gt 0) {
            $Risk = ('The following security-relevant audit subcategories are not audited at all, limiting incident detection and investigation: {0}.' -f ($NotAudited -join ', '))
        }

        New-AssessmentADFinding `
            -AssessmentId $AssessmentId `
            -CheckId $CheckId `
            -CheckName $CheckName `
            -Category 'AuditingAndLogging' `
            -Title ('Audit policy coverage: {0}' -f $Target) `
            -Description 'Evaluates whether security-relevant Advanced Audit Policy subcategories have auditing enabled.' `
            -Severity $Severity `
            -Confidence 'High' `
            -Status 'Finding' `
            -AffectedObject ([PSCustomObject][ordered]@{ Name = $Target; ObjectClass = 'Computer'; Enabled = $null }) `
            -ObjectType 'Computer' `
            -DistinguishedName $null `
            -SamAccountName $null `
            -ObjectGuid ([guid]::Empty) `
            -Evidence (
                [PSCustomObject][ordered]@{
                    EvaluatedSubcategories = $Evaluated
                    NotAuditedSubcategories = $NotAudited
                    CollectionMethod        = 'WinRM'
                }
            ) `
            -Risk $Risk `
            -Recommendation 'Enable auditing (Success and/or Failure, per Microsoft''s audit policy recommendations) for every security-relevant subcategory, and forward the resulting events to a central log/SIEM.' `
            -References @('https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations') `
            -Domain $null `
            -Forest $null `
            -DomainController $null
    }
}
