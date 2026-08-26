#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentHtml {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )]
        [object]$Assessment,

        [Parameter(Mandatory)]
        [string]$Path
    )

    process {

        if ($null -eq $Assessment) {
            throw 'Assessment cannot be null.'
        }

        if (-not $Assessment.PSObject.Properties['AssessmentId']) {
            throw 'The supplied object is not a valid TechHubADAssessmentResult.'
        }

        try {

            # ============================================================
            # DESTINATION
            # ============================================================

            $Directory = Split-Path -Path $Path -Parent

            if (-not [string]::IsNullOrWhiteSpace($Directory)) {

                if (-not (Test-Path -LiteralPath $Directory)) {

                    New-Item `
                        -Path $Directory `
                        -ItemType Directory `
                        -Force `
                        -ErrorAction Stop |
                        Out-Null
                }
            }

            # ============================================================
            # HELPERS
            # ============================================================

            function ConvertTo-HtmlSafe {
                param(
                    [AllowNull()]
                    [object]$Value
                )

                if ($null -eq $Value) {
                    return ''
                }

                [System.Net.WebUtility]::HtmlEncode(
                    [string]$Value
                )
            }

            function ConvertTo-HtmlJson {
                param(
                    [AllowNull()]
                    [object]$Value
                )

                if ($null -eq $Value) {
                    return ''
                }

                $Json = $Value |
                    ConvertTo-Json `
                        -Depth 12 `
                        -Compress

                return [System.Net.WebUtility]::HtmlEncode(
                    [string]$Json
                )
            }

            function Get-SeverityClass {
                param(
                    [AllowNull()]
                    [object]$Severity
                )

                switch -Regex ([string]$Severity) {

                    '^Critical$' {
                        return 'severity-critical'
                    }

                    '^High$' {
                        return 'severity-high'
                    }

                    '^Medium$' {
                        return 'severity-medium'
                    }

                    '^Low$' {
                        return 'severity-low'
                    }

                    '^Informational$' {
                        return 'severity-info'
                    }

                    default {
                        return 'severity-neutral'
                    }
                }
            }

            function Get-StatusClass {
                param(
                    [AllowNull()]
                    [object]$Status
                )

                switch -Regex ([string]$Status) {

                    '^(Available|Complete|Open|Finding)$' {
                        return 'status-success'
                    }

                    '^(Partial|Warning)$' {
                        return 'status-warning'
                    }

                    '^(Error|Failed)$' {
                        return 'status-danger'
                    }

                    '^(NotAvailable|NotApplicable)$' {
                        return 'status-neutral'
                    }

                    default {
                        return 'status-neutral'
                    }
                }
            }

            # ============================================================
            # ASSESSMENT METADATA
            # ============================================================

            $AssessmentId = ConvertTo-HtmlSafe $Assessment.AssessmentId

            $StartedAt = ''

            if ($null -ne $Assessment.StartedAt) {

                $StartedAt =
                    ConvertTo-HtmlSafe (
                        ([datetime]$Assessment.StartedAt).ToString('yyyy-MM-dd HH:mm:ss UTC')
                    )
            }

            $CompletedAt = ''

            if ($null -ne $Assessment.CompletedAt) {

                $CompletedAt =
                    ConvertTo-HtmlSafe (
                        ([datetime]$Assessment.CompletedAt).ToString('yyyy-MM-dd HH:mm:ss UTC')
                    )
            }

            $Duration = ''

            if (
                $Assessment.PSObject.Properties['Duration'] -and
                $null -ne $Assessment.Duration
            ) {

                $Duration =
                    ConvertTo-HtmlSafe (
                        ([timespan]$Assessment.Duration).ToString()
                    )
            }

            $Domain = ''

            if (
                $Assessment.PSObject.Properties['Domain'] -and
                $null -ne $Assessment.Domain
            ) {
                $Domain = ConvertTo-HtmlSafe $Assessment.Domain
            }

            $Forest = ''

            if (
                $Assessment.PSObject.Properties['Forest'] -and
                $null -ne $Assessment.Forest
            ) {
                $Forest = ConvertTo-HtmlSafe $Assessment.Forest
            }

            $DomainController = ''

            if (
                $Assessment.PSObject.Properties['DomainController'] -and
                $null -ne $Assessment.DomainController
            ) {
                $DomainController =
                    ConvertTo-HtmlSafe $Assessment.DomainController
            }

            $ProviderStatus = ''

            if (
                $Assessment.PSObject.Properties['ProviderStatus'] -and
                $null -ne $Assessment.ProviderStatus
            ) {
                $ProviderStatus =
                    ConvertTo-HtmlSafe $Assessment.ProviderStatus
            }

            $DataAvailability = ''

            if (
                $Assessment.PSObject.Properties['DataAvailability'] -and
                $null -ne $Assessment.DataAvailability
            ) {
                $DataAvailability =
                    ConvertTo-HtmlSafe $Assessment.DataAvailability
            }

            # ============================================================
            # SUMMARY COUNTS
            # ============================================================

            $FindingsCount = 0
            $ObservationsCount = 0
            $InventoryCount = 0
            $HealthCount = 0
            $ProviderResultsCount = 0
            $ChecksDiscovered = 0
            $ChecksExecuted = 0
            $ChecksSkipped = 0
            $ChecksFailed = 0

            if ($null -ne $Assessment.Summary) {

                if ($Assessment.Summary.PSObject.Properties['FindingsCount']) {
                    $FindingsCount = [int]$Assessment.Summary.FindingsCount
                }

                if ($Assessment.Summary.PSObject.Properties['ObservationsCount']) {
                    $ObservationsCount = [int]$Assessment.Summary.ObservationsCount
                }

                if ($Assessment.Summary.PSObject.Properties['InventoryCount']) {
                    $InventoryCount = [int]$Assessment.Summary.InventoryCount
                }

                if ($Assessment.Summary.PSObject.Properties['HealthCount']) {
                    $HealthCount = [int]$Assessment.Summary.HealthCount
                }

                if ($Assessment.Summary.PSObject.Properties['ProviderResultsCount']) {
                    $ProviderResultsCount =
                        [int]$Assessment.Summary.ProviderResultsCount
                }

                if ($Assessment.Summary.PSObject.Properties['ChecksDiscovered']) {
                    $ChecksDiscovered =
                        [int]$Assessment.Summary.ChecksDiscovered
                }

                if ($Assessment.Summary.PSObject.Properties['ChecksExecuted']) {
                    $ChecksExecuted =
                        [int]$Assessment.Summary.ChecksExecuted
                }

                if ($Assessment.Summary.PSObject.Properties['ChecksSkipped']) {
                    $ChecksSkipped =
                        [int]$Assessment.Summary.ChecksSkipped
                }

                if ($Assessment.Summary.PSObject.Properties['ChecksFailed']) {
                    $ChecksFailed =
                        [int]$Assessment.Summary.ChecksFailed
                }
            }

            # ============================================================
            # SEVERITY COUNTS
            # ============================================================

            $CriticalCount = 0
            $HighCount = 0
            $MediumCount = 0
            $LowCount = 0
            $InformationalCount = 0

            if (
                $null -ne $Assessment.Summary -and
                $Assessment.Summary.PSObject.Properties['SeverityCounts']
            ) {

                $SeverityCounts = $Assessment.Summary.SeverityCounts

                if ($SeverityCounts.Contains('Critical')) {
                    $CriticalCount = [int]$SeverityCounts['Critical']
                }

                if ($SeverityCounts.Contains('High')) {
                    $HighCount = [int]$SeverityCounts['High']
                }

                if ($SeverityCounts.Contains('Medium')) {
                    $MediumCount = [int]$SeverityCounts['Medium']
                }

                if ($SeverityCounts.Contains('Low')) {
                    $LowCount = [int]$SeverityCounts['Low']
                }

                if ($SeverityCounts.Contains('Informational')) {
                    $InformationalCount =
                        [int]$SeverityCounts['Informational']
                }
            }

            # ============================================================
            # FINDING TABLE
            # ============================================================

            $FindingRows = New-Object System.Text.StringBuilder

            foreach ($Finding in @($Assessment.Findings)) {

                if ($null -eq $Finding) {
                    continue
                }

                $CheckId = ''
                $CheckName = ''
                $FindingId = ''
                $Title = ''
                $Category = ''
                $Severity = ''
                $Confidence = ''
                $Status = ''
                $ObjectType = ''
                $ObjectName = ''
                $DistinguishedName = ''
                $Risk = ''
                $Recommendation = ''
                $Evidence = ''
                $References = ''

                if ($Finding.PSObject.Properties['CheckId']) {
                    $CheckId = ConvertTo-HtmlSafe $Finding.CheckId
                }

                if ($Finding.PSObject.Properties['CheckName']) {
                    $CheckName = ConvertTo-HtmlSafe $Finding.CheckName
                }

                if ($Finding.PSObject.Properties['FindingId']) {
                    $FindingId = ConvertTo-HtmlSafe $Finding.FindingId
                }

                if ($Finding.PSObject.Properties['Title']) {
                    $Title = ConvertTo-HtmlSafe $Finding.Title
                }

                if ($Finding.PSObject.Properties['Category']) {
                    $Category = ConvertTo-HtmlSafe $Finding.Category
                }

                if ($Finding.PSObject.Properties['Severity']) {
                    $Severity = ConvertTo-HtmlSafe $Finding.Severity
                }

                if ($Finding.PSObject.Properties['Confidence']) {
                    $Confidence = ConvertTo-HtmlSafe $Finding.Confidence
                }

                if ($Finding.PSObject.Properties['Status']) {
                    $Status = ConvertTo-HtmlSafe $Finding.Status
                }

                if ($Finding.PSObject.Properties['ObjectType']) {
                    $ObjectType = ConvertTo-HtmlSafe $Finding.ObjectType
                }

                if ($Finding.PSObject.Properties['AffectedObject']) {
                    $ObjectName =
                        ConvertTo-HtmlJson $Finding.AffectedObject
                }

                if ($Finding.PSObject.Properties['DistinguishedName']) {
                    $DistinguishedName =
                        ConvertTo-HtmlSafe $Finding.DistinguishedName
                }

                if ($Finding.PSObject.Properties['Risk']) {
                    $Risk = ConvertTo-HtmlSafe $Finding.Risk
                }

                if ($Finding.PSObject.Properties['Recommendation']) {
                    $Recommendation =
                        ConvertTo-HtmlSafe $Finding.Recommendation
                }

                if ($Finding.PSObject.Properties['Evidence']) {
                    $Evidence =
                        ConvertTo-HtmlJson $Finding.Evidence
                }

                if ($Finding.PSObject.Properties['References']) {

                    $ReferenceItems = @()

                    foreach ($Reference in @($Finding.References)) {

                        if (-not [string]::IsNullOrWhiteSpace([string]$Reference)) {

                            $ReferenceItems +=
                                '<li>' +
                                (ConvertTo-HtmlSafe $Reference) +
                                '</li>'
                        }
                    }

                    if ($ReferenceItems.Count -gt 0) {

                        $References =
                            '<ul class="reference-list">' +
                            ($ReferenceItems -join '') +
                            '</ul>'
                    }
                }

                $SeverityClass =
                    Get-SeverityClass $Finding.Severity

                $StatusClass =
                    Get-StatusClass $Finding.Status

                [void]$FindingRows.AppendLine(@"
<tr>
    <td>
        <span class="mono">$CheckId</span>
        <div class="subtle">$CheckName</div>
    </td>

    <td>
        <strong>$Title</strong>
        <div class="subtle">$FindingId</div>
    </td>

    <td>
        <span class="badge $SeverityClass">
            $Severity
        </span>
    </td>

    <td>
        <span class="badge $StatusClass">
            $Status
        </span>
    </td>

    <td>$Confidence</td>

    <td>
        <strong>$ObjectType</strong>
        <div class="object-json">$ObjectName</div>
        <div class="dn">$DistinguishedName</div>
    </td>

    <td>
        <details>
            <summary>View details</summary>

            <div class="detail-block">
                <h4>Risk</h4>
                <p>$Risk</p>
            </div>

            <div class="detail-block">
                <h4>Recommendation</h4>
                <p>$Recommendation</p>
            </div>

            <div class="detail-block">
                <h4>Evidence</h4>
                <pre>$Evidence</pre>
            </div>

            <div class="detail-block">
                <h4>References</h4>
                $References
            </div>
        </details>
    </td>
</tr>
"@)
            }

            if ($FindingRows.Length -eq 0) {

                [void]$FindingRows.AppendLine(@"
<tr>
    <td colspan="7">
        <div class="empty-state">
            <div class="empty-icon">✓</div>
            <strong>No security findings were reported.</strong>
            <span>The assessment did not return any finding records.</span>
        </div>
    </td>
</tr>
"@)
            }

            # ============================================================
            # INVENTORY TABLE
            # ============================================================

            $InventoryRows =
                New-Object System.Text.StringBuilder

            foreach ($Item in @($Assessment.Inventory)) {

                if ($null -eq $Item) {
                    continue
                }

                $ComputerName = ''
                $Collector = ''
                $Status = ''
                $DataText = ''
                $ErrorText = ''

                if ($Item.PSObject.Properties['ComputerName']) {
                    $ComputerName =
                        ConvertTo-HtmlSafe $Item.ComputerName
                }

                if ($Item.PSObject.Properties['Collector']) {
                    $Collector =
                        ConvertTo-HtmlSafe $Item.Collector
                }

                if ($Item.PSObject.Properties['Status']) {
                    $Status =
                        ConvertTo-HtmlSafe $Item.Status
                }

                if (
                    $Item.PSObject.Properties['Data'] -and
                    $null -ne $Item.Data
                ) {
                    $DataText =
                        ConvertTo-HtmlJson $Item.Data
                }

                if (
                    $Item.PSObject.Properties['Error'] -and
                    $null -ne $Item.Error
                ) {
                    $ErrorText =
                        ConvertTo-HtmlSafe $Item.Error
                }

                $StatusClass =
                    Get-StatusClass $Item.Status

                [void]$InventoryRows.AppendLine(@"
<tr>
    <td class="mono">$ComputerName</td>
    <td>$Collector</td>
    <td>
        <span class="badge $StatusClass">$Status</span>
    </td>
    <td>
        <details>
            <summary>View data</summary>
            <pre>$DataText</pre>
        </details>
    </td>
    <td>$ErrorText</td>
</tr>
"@)
            }

            if ($InventoryRows.Length -eq 0) {

                [void]$InventoryRows.AppendLine(@"
<tr>
    <td colspan="5">
        <div class="empty-state">
            <strong>No inventory records.</strong>
        </div>
    </td>
</tr>
"@)
            }

            # ============================================================
            # CHECK EXECUTION TABLE
            # ============================================================

            $CheckRows =
                New-Object System.Text.StringBuilder

            if (
                $Assessment.PSObject.Properties['Metadata'] -and
                $null -ne $Assessment.Metadata -and
                $Assessment.Metadata.PSObject.Properties['CheckResults']
            ) {

                foreach ($CheckResult in @($Assessment.Metadata.CheckResults)) {

                    if ($null -eq $CheckResult) {
                        continue
                    }

                    $CheckId = ''
                    $CheckName = ''
                    $Status = ''
                    $ErrorType = ''
                    $ErrorMessage = ''
                    $Duration = ''

                    if ($CheckResult.PSObject.Properties['CheckId']) {
                        $CheckId =
                            ConvertTo-HtmlSafe $CheckResult.CheckId
                    }

                    if ($CheckResult.PSObject.Properties['CheckName']) {
                        $CheckName =
                            ConvertTo-HtmlSafe $CheckResult.CheckName
                    }

                    if ($CheckResult.PSObject.Properties['Status']) {
                        $Status =
                            ConvertTo-HtmlSafe $CheckResult.Status
                    }

                    if ($CheckResult.PSObject.Properties['ErrorType']) {
                        $ErrorType =
                            ConvertTo-HtmlSafe $CheckResult.ErrorType
                    }

                    if ($CheckResult.PSObject.Properties['ErrorMessage']) {
                        $ErrorMessage =
                            ConvertTo-HtmlSafe $CheckResult.ErrorMessage
                    }

                    if ($CheckResult.PSObject.Properties['Duration']) {
                        $Duration =
                            ConvertTo-HtmlSafe $CheckResult.Duration
                    }

                    $StatusClass =
                        Get-StatusClass $CheckResult.Status

                    [void]$CheckRows.AppendLine(@"
<tr>
    <td class="mono">$CheckId</td>
    <td>$CheckName</td>
    <td>
        <span class="badge $StatusClass">$Status</span>
    </td>
    <td>$ErrorType</td>
    <td>$Duration</td>
    <td>$ErrorMessage</td>
</tr>
"@)
                }
            }

            if ($CheckRows.Length -eq 0) {

                [void]$CheckRows.AppendLine(@"
<tr>
    <td colspan="6">
        <div class="empty-state">
            <strong>No check execution errors were recorded.</strong>
        </div>
    </td>
</tr>
"@)
            }

            # ============================================================
            # HTML DOCUMENT
            # ============================================================

            $Html = @"
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1">

<meta name="generator"
      content="TechHub.ActiveDirectory">

<title>
TechHub Active Directory Security Assessment
</title>

<style>

/* ============================================================
   BASE
   ============================================================ */

:root {

    --navy: #14213d;
    --navy-dark: #0d172b;

    --blue: #2563eb;
    --blue-light: #eff6ff;

    --green: #15803d;
    --green-light: #f0fdf4;

    --amber: #b45309;
    --amber-light: #fffbeb;

    --red: #b91c1c;
    --red-light: #fef2f2;

    --purple: #6d28d9;
    --purple-light: #f5f3ff;

    --gray-50: #f8fafc;
    --gray-100: #f1f5f9;
    --gray-200: #e2e8f0;
    --gray-300: #cbd5e1;
    --gray-500: #64748b;
    --gray-600: #475569;
    --gray-700: #334155;
    --gray-900: #0f172a;

    --white: #ffffff;

    --shadow:
        0 4px 16px rgba(15, 23, 42, 0.08);

    --radius: 10px;
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {

    margin: 0;

    background:
        linear-gradient(
            180deg,
            #eef2f7 0%,
            #f8fafc 100%
        );

    color: var(--gray-900);

    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Helvetica,
        Arial,
        sans-serif;

    font-size: 14px;

    line-height: 1.55;
}

/* ============================================================
   LAYOUT
   ============================================================ */

.page {

    max-width: 1500px;

    margin: 0 auto;

    padding: 32px;
}

.report {

    background: var(--white);

    border-radius: var(--radius);

    box-shadow: var(--shadow);

    overflow: hidden;
}

/* ============================================================
   HEADER
   ============================================================ */

.header {

    background:
        linear-gradient(
            135deg,
            var(--navy-dark),
            var(--navy)
        );

    color: var(--white);

    padding: 38px 42px;

    position: relative;
}

.header::after {

    content: "";

    position: absolute;

    left: 0;
    right: 0;
    bottom: 0;

    height: 4px;

    background:
        linear-gradient(
            90deg,
            #2563eb,
            #7c3aed
        );
}

.brand {

    display: flex;

    align-items: center;

    gap: 16px;
}

.brand-mark {

    width: 48px;
    height: 48px;

    border-radius: 10px;

    background: rgba(255,255,255,0.1);

    border: 1px solid rgba(255,255,255,0.18);

    display: flex;

    align-items: center;
    justify-content: center;

    font-weight: 800;

    letter-spacing: -1px;

    font-size: 18px;
}

.brand-name {

    font-size: 13px;

    text-transform: uppercase;

    letter-spacing: 1.5px;

    opacity: .72;
}

.header h1 {

    margin: 28px 0 8px;

    font-size: 32px;

    line-height: 1.15;

    letter-spacing: -0.7px;
}

.header-subtitle {

    margin: 0;

    color: #cbd5e1;

    font-size: 15px;
}

/* ============================================================
   METADATA
   ============================================================ */

.metadata {

    display: grid;

    grid-template-columns:
        repeat(
            4,
            minmax(0, 1fr)
        );

    border-bottom: 1px solid var(--gray-200);

    background: var(--gray-50);
}

.metadata-item {

    padding: 18px 22px;

    border-right: 1px solid var(--gray-200);

    min-width: 0;
}

.metadata-item:last-child {
    border-right: 0;
}

.metadata-label {

    color: var(--gray-500);

    font-size: 11px;

    font-weight: 700;

    text-transform: uppercase;

    letter-spacing: .7px;

    margin-bottom: 4px;
}

.metadata-value {

    font-size: 13px;

    font-weight: 600;

    overflow-wrap: anywhere;
}

.mono {

    font-family:
        Consolas,
        "Liberation Mono",
        monospace;

    font-size: 12px;
}

/* ============================================================
   CONTENT
   ============================================================ */

.content {

    padding: 34px 38px 42px;
}

.section {

    margin-top: 36px;
}

.section:first-child {
    margin-top: 0;
}

.section-title {

    display: flex;

    align-items: center;

    gap: 10px;

    margin: 0 0 16px;

    color: var(--gray-900);

    font-size: 20px;

    letter-spacing: -.2px;
}

.section-title::before {

    content: "";

    display: block;

    width: 4px;

    height: 22px;

    border-radius: 3px;

    background: var(--blue);
}

/* ============================================================
   KPI CARDS
   ============================================================ */

.kpi-grid {

    display: grid;

    grid-template-columns:
        repeat(
            5,
            minmax(0, 1fr)
        );

    gap: 14px;
}

.kpi {

    border: 1px solid var(--gray-200);

    border-radius: 9px;

    padding: 18px;

    background: var(--white);

    box-shadow:
        0 2px 7px rgba(15,23,42,.04);
}

.kpi-label {

    color: var(--gray-500);

    font-size: 11px;

    text-transform: uppercase;

    font-weight: 700;

    letter-spacing: .6px;
}

.kpi-value {

    display: block;

    margin-top: 4px;

    font-size: 28px;

    line-height: 1;

    font-weight: 750;
}

.kpi-critical {
    border-top: 3px solid #dc2626;
}

.kpi-high {
    border-top: 3px solid #ea580c;
}

.kpi-medium {
    border-top: 3px solid #d97706;
}

.kpi-low {
    border-top: 3px solid #2563eb;
}

.kpi-info {
    border-top: 3px solid #64748b;
}

/* ============================================================
   STATUS
   ============================================================ */

.status-row {

    display: grid;

    grid-template-columns:
        repeat(
            3,
            minmax(0, 1fr)
        );

    gap: 14px;

    margin-top: 14px;
}

.status-card {

    padding: 16px;

    border: 1px solid var(--gray-200);

    border-radius: 9px;

    background: var(--gray-50);
}

.status-card-label {

    color: var(--gray-500);

    font-size: 11px;

    text-transform: uppercase;

    font-weight: 700;

    letter-spacing: .6px;
}

.status-card-value {

    margin-top: 5px;

    font-size: 15px;

    font-weight: 700;
}

/* ============================================================
   BADGES
   ============================================================ */

.badge {

    display: inline-flex;

    align-items: center;

    padding: 4px 9px;

    border-radius: 999px;

    font-size: 11px;

    font-weight: 750;

    white-space: nowrap;
}

.severity-critical {
    background: #fee2e2;
    color: #991b1b;
}

.severity-high {
    background: #ffedd5;
    color: #9a3412;
}

.severity-medium {
    background: #fef3c7;
    color: #92400e;
}

.severity-low {
    background: #dbeafe;
    color: #1d4ed8;
}

.severity-info {
    background: #e2e8f0;
    color: #475569;
}

.severity-neutral {
    background: #f1f5f9;
    color: #475569;
}

.status-success {
    background: #dcfce7;
    color: #166534;
}

.status-warning {
    background: #fef3c7;
    color: #92400e;
}

.status-danger {
    background: #fee2e2;
    color: #991b1b;
}

.status-neutral {
    background: #e2e8f0;
    color: #475569;
}

/* ============================================================
   TABLES
   ============================================================ */

.table-wrapper {

    width: 100%;

    overflow-x: auto;

    border:
        1px solid var(--gray-200);

    border-radius: 9px;

    background: var(--white);
}

table {

    width: 100%;

    border-collapse: collapse;

    min-width: 900px;
}

thead th {

    background: var(--gray-100);

    color: var(--gray-600);

    font-size: 11px;

    font-weight: 750;

    text-transform: uppercase;

    letter-spacing: .5px;

    padding: 12px;

    border-bottom:
        1px solid var(--gray-200);

    text-align: left;

    white-space: nowrap;
}

tbody td {

    padding: 13px 12px;

    border-bottom:
        1px solid var(--gray-100);

    vertical-align: top;

    color: var(--gray-700);
}

tbody tr:last-child td {
    border-bottom: 0;
}

tbody tr:hover {
    background: #fafcff;
}

.subtle {

    margin-top: 3px;

    color: var(--gray-500);

    font-size: 11px;
}

.dn {

    margin-top: 5px;

    color: var(--gray-500);

    font-family:
        Consolas,
        monospace;

    font-size: 10px;

    overflow-wrap: anywhere;
}

.object-json {

    margin-top: 5px;

    max-width: 280px;

    font-family:
        Consolas,
        monospace;

    font-size: 10px;

    color: var(--gray-600);

    overflow-wrap: anywhere;
}

details {

    border: 1px solid var(--gray-200);

    border-radius: 7px;

    padding: 8px 10px;

    background: var(--gray-50);
}

details summary {

    cursor: pointer;

    color: var(--blue);

    font-size: 12px;

    font-weight: 700;
}

.detail-block {

    margin-top: 14px;

    padding-top: 12px;

    border-top: 1px solid var(--gray-200);
}

.detail-block h4 {

    margin: 0 0 5px;

    font-size: 11px;

    color: var(--gray-500);

    text-transform: uppercase;

    letter-spacing: .5px;
}

.detail-block p {
    margin: 0;
}

pre {

    margin: 0;

    padding: 10px;

    border-radius: 6px;

    background: #0f172a;

    color: #e2e8f0;

    white-space: pre-wrap;

    word-break: break-word;

    font-family:
        Consolas,
        "Liberation Mono",
        monospace;

    font-size: 11px;

    line-height: 1.5;
}

.reference-list {

    margin: 0;

    padding-left: 18px;

    font-size: 12px;
}

/* ============================================================
   EMPTY STATE
   ============================================================ */

.empty-state {

    display: flex;

    flex-direction: column;

    align-items: center;

    justify-content: center;

    gap: 5px;

    padding: 30px;

    color: var(--gray-500);

    text-align: center;
}

.empty-state strong {
    color: var(--gray-700);
}

.empty-icon {

    display: flex;

    width: 38px;
    height: 38px;

    align-items: center;
    justify-content: center;

    border-radius: 50%;

    background: var(--green-light);

    color: var(--green);

    font-size: 18px;

    font-weight: 800;

    margin-bottom: 5px;
}

/* ============================================================
   FOOTER
   ============================================================ */

.footer {

    margin-top: 42px;

    padding-top: 18px;

    border-top:
        1px solid var(--gray-200);

    color: var(--gray-500);

    font-size: 11px;

    display: flex;

    justify-content: space-between;

    gap: 20px;

    flex-wrap: wrap;
}

/* ============================================================
   RESPONSIVE
   ============================================================ */

@media (max-width: 1100px) {

    .metadata {
        grid-template-columns:
            repeat(
                2,
                minmax(0, 1fr)
            );
    }

    .kpi-grid {
        grid-template-columns:
            repeat(
                3,
                minmax(0, 1fr)
            );
    }
}

@media (max-width: 700px) {

    .page {
        padding: 0;
    }

    .report {
        border-radius: 0;
    }

    .header {
        padding: 28px 22px;
    }

    .content {
        padding: 26px 20px;
    }

    .metadata {
        grid-template-columns: 1fr;
    }

    .metadata-item {
        border-right: 0;

        border-bottom:
            1px solid var(--gray-200);
    }

    .kpi-grid {
        grid-template-columns: 1fr 1fr;
    }

    .status-row {
        grid-template-columns: 1fr;
    }

    .header h1 {
        font-size: 26px;
    }
}

/* ============================================================
   PRINT
   ============================================================ */

@media print {

    body {
        background: white;
    }

    .page {
        max-width: none;
        padding: 0;
    }

    .report {
        box-shadow: none;
        border-radius: 0;
    }

    .header {
        print-color-adjust: exact;
        -webkit-print-color-adjust: exact;
    }

    .kpi,
    .status-card,
    .table-wrapper {
        break-inside: avoid;
    }

    details {
        border: 0;
        padding: 0;
        background: transparent;
    }

    details summary {
        display: none;
    }

    details .detail-block {
        display: block;
    }

    @page {
        margin: 15mm;
    }
}

</style>

</head>

<body>

<div class="page">

<div class="report">

<!-- ============================================================
     HEADER
     ============================================================ -->

<header class="header">

    <div class="brand">

        <div class="brand-mark">
            TH
        </div>

        <div>

            <div class="brand-name">
                TechHub Security Assessment
            </div>

        </div>

    </div>

    <h1>
        Active Directory Security Assessment
    </h1>

    <p class="header-subtitle">
        Read-only security and configuration assessment report
    </p>

</header>

<!-- ============================================================
     METADATA
     ============================================================ -->

<section class="metadata">

    <div class="metadata-item">

        <div class="metadata-label">
            Assessment ID
        </div>

        <div class="metadata-value mono">
            $AssessmentId
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Domain
        </div>

        <div class="metadata-value">
            $Domain
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Forest
        </div>

        <div class="metadata-value">
            $Forest
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Domain Controller
        </div>

        <div class="metadata-value">
            $DomainController
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Provider
        </div>

        <div class="metadata-value">
            $ProviderStatus
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Data Availability
        </div>

        <div class="metadata-value">
            $DataAvailability
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Started
        </div>

        <div class="metadata-value">
            $StartedAt
        </div>

    </div>

    <div class="metadata-item">

        <div class="metadata-label">
            Completed
        </div>

        <div class="metadata-value">
            $CompletedAt
        </div>

    </div>

</section>

<div class="content">

<!-- ============================================================
     EXECUTIVE SUMMARY
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Executive Summary
    </h2>

    <div class="kpi-grid">

        <div class="kpi kpi-critical">

            <span class="kpi-label">
                Critical
            </span>

            <span class="kpi-value">
                $CriticalCount
            </span>

        </div>

        <div class="kpi kpi-high">

            <span class="kpi-label">
                High
            </span>

            <span class="kpi-value">
                $HighCount
            </span>

        </div>

        <div class="kpi kpi-medium">

            <span class="kpi-label">
                Medium
            </span>

            <span class="kpi-value">
                $MediumCount
            </span>

        </div>

        <div class="kpi kpi-low">

            <span class="kpi-label">
                Low
            </span>

            <span class="kpi-value">
                $LowCount
            </span>

        </div>

        <div class="kpi kpi-info">

            <span class="kpi-label">
                Informational
            </span>

            <span class="kpi-value">
                $InformationalCount
            </span>

        </div>

    </div>

    <div class="status-row">

        <div class="status-card">

            <div class="status-card-label">
                Total Findings
            </div>

            <div class="status-card-value">
                $FindingsCount
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Checks Executed
            </div>

            <div class="status-card-value">
                $ChecksExecuted / $ChecksDiscovered
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Assessment Duration
            </div>

            <div class="status-card-value">
                $Duration
            </div>

        </div>

    </div>

</section>

<!-- ============================================================
     ASSESSMENT STATUS
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Assessment Status
    </h2>

    <div class="status-row">

        <div class="status-card">

            <div class="status-card-label">
                Provider Status
            </div>

            <div class="status-card-value">
                $ProviderStatus
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Data Availability
            </div>

            <div class="status-card-value">
                $DataAvailability
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Failed Checks
            </div>

            <div class="status-card-value">
                $ChecksFailed
            </div>

        </div>

    </div>

</section>

<!-- ============================================================
     FINDINGS
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Security Findings
    </h2>

    <div class="table-wrapper">

        <table>

            <thead>

                <tr>

                    <th>
                        Check
                    </th>

                    <th>
                        Finding
                    </th>

                    <th>
                        Severity
                    </th>

                    <th>
                        Status
                    </th>

                    <th>
                        Confidence
                    </th>

                    <th>
                        Affected Object
                    </th>

                    <th>
                        Details
                    </th>

                </tr>

            </thead>

            <tbody>

                $FindingRows

            </tbody>

        </table>

    </div>

</section>

<!-- ============================================================
     INVENTORY
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Inventory
    </h2>

    <div class="table-wrapper">

        <table>

            <thead>

                <tr>

                    <th>
                        Computer
                    </th>

                    <th>
                        Collector
                    </th>

                    <th>
                        Status
                    </th>

                    <th>
                        Data
                    </th>

                    <th>
                        Error
                    </th>

                </tr>

            </thead>

            <tbody>

                $InventoryRows

            </tbody>

        </table>

    </div>

</section>

<!-- ============================================================
     CHECK EXECUTION
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Check Execution
    </h2>

    <div class="table-wrapper">

        <table>

            <thead>

                <tr>

                    <th>
                        Check ID
                    </th>

                    <th>
                        Check Name
                    </th>

                    <th>
                        Status
                    </th>

                    <th>
                        Error Type
                    </th>

                    <th>
                        Duration
                    </th>

                    <th>
                        Error Message
                    </th>

                </tr>

            </thead>

            <tbody>

                $CheckRows

            </tbody>

        </table>

    </div>

</section>

<!-- ============================================================
     TECHNICAL SUMMARY
     ============================================================ -->

<section class="section">

    <h2 class="section-title">
        Technical Summary
    </h2>

    <div class="status-row">

        <div class="status-card">

            <div class="status-card-label">
                Observations
            </div>

            <div class="status-card-value">
                $ObservationsCount
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Inventory Records
            </div>

            <div class="status-card-value">
                $InventoryCount
            </div>

        </div>

        <div class="status-card">

            <div class="status-card-label">
                Provider Results
            </div>

            <div class="status-card-value">
                $ProviderResultsCount
            </div>

        </div>

    </div>

</section>

<!-- ============================================================
     FOOTER
     ============================================================ -->

<footer class="footer">

    <div>
        Generated by
        <strong>TechHub.ActiveDirectory</strong>
    </div>

    <div>
        Read-only assessment
        ·
        No Active Directory modifications performed
    </div>

</footer>

</div>

</div>

</div>

</body>

</html>
"@

            # ============================================================
            # WRITE UTF-8 HTML
            # ============================================================

            [System.IO.File]::WriteAllText(
                $Path,
                $Html,
                [System.Text.UTF8Encoding]::new($false)
            )

            Get-Item -LiteralPath $Path
        }
        catch {

            throw `
                "Unable to export TechHub AD assessment to HTML: $($_.Exception.Message)"
        }
    }
}