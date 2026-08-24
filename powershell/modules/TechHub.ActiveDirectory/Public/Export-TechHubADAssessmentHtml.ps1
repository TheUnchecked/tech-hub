#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-TechHubADAssessmentHtml {
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
            # ------------------------------------------------------------
            # Destination directory
            # ------------------------------------------------------------

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

            # ------------------------------------------------------------
            # Assessment metadata
            # ------------------------------------------------------------

            $AssessmentId = [System.Net.WebUtility]::HtmlEncode(
                [string]$Assessment.AssessmentId
            )

            $StartedAt = ''

            if ($null -ne $Assessment.StartedAt) {
                $StartedAt = [System.Net.WebUtility]::HtmlEncode(
                    ([datetime]$Assessment.StartedAt).ToString('u')
                )
            }

            $CompletedAt = ''

            if ($null -ne $Assessment.CompletedAt) {
                $CompletedAt = [System.Net.WebUtility]::HtmlEncode(
                    ([datetime]$Assessment.CompletedAt).ToString('u')
                )
            }

            $ProviderStatus = ''

            if ($null -ne $Assessment.ProviderStatus) {
                $ProviderStatus = [System.Net.WebUtility]::HtmlEncode(
                    [string]$Assessment.ProviderStatus
                )
            }

            $DataAvailability = ''

            if ($null -ne $Assessment.DataAvailability) {
                $DataAvailability = [System.Net.WebUtility]::HtmlEncode(
                    [string]$Assessment.DataAvailability
                )
            }

            # ------------------------------------------------------------
            # Findings
            # ------------------------------------------------------------

            $FindingRows = New-Object System.Text.StringBuilder

            foreach ($Finding in @($Assessment.Findings)) {

                $CheckId = ''
                $Title = ''
                $Severity = ''
                $Status = ''
                $ReadOnly = 'True'

                if ($Finding.PSObject.Properties['CheckId']) {
                    $CheckId = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Finding.CheckId
                    )
                }

                if ($Finding.PSObject.Properties['Title']) {
                    $Title = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Finding.Title
                    )
                }

                if ($Finding.PSObject.Properties['Severity']) {
                    $Severity = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Finding.Severity
                    )
                }

                if ($Finding.PSObject.Properties['Status']) {
                    $Status = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Finding.Status
                    )
                }

                if ($Finding.PSObject.Properties['IsReadOnly']) {
                    $ReadOnly = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Finding.IsReadOnly
                    )
                }

                [void]$FindingRows.AppendLine(
                    "<tr><td>$CheckId</td><td>$Title</td><td>$Severity</td><td>$Status</td><td>$ReadOnly</td></tr>"
                )
            }

            if ($FindingRows.Length -eq 0) {
                [void]$FindingRows.AppendLine(
                    '<tr><td colspan="5">No findings.</td></tr>'
                )
            }

            # ------------------------------------------------------------
            # Inventory
            # ------------------------------------------------------------

            $InventoryRows = New-Object System.Text.StringBuilder

            foreach ($Item in @($Assessment.Inventory)) {

                $ComputerName = ''
                $Collector = ''
                $Status = ''
                $ReadOnly = 'True'
                $DataText = ''
                $ErrorText = ''

                if ($Item.PSObject.Properties['ComputerName']) {
                    $ComputerName = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Item.ComputerName
                    )
                }

                if ($Item.PSObject.Properties['Collector']) {
                    $Collector = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Item.Collector
                    )
                }

                if ($Item.PSObject.Properties['Status']) {
                    $Status = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Item.Status
                    )
                }

                if ($Item.PSObject.Properties['IsReadOnly']) {
                    $ReadOnly = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Item.IsReadOnly
                    )
                }

                if (
                    $Item.PSObject.Properties['Data'] -and
                    $null -ne $Item.Data
                ) {
                    $DataJson = $Item.Data |
                        ConvertTo-Json `
                            -Depth 10 `
                            -Compress

                    $DataText = [System.Net.WebUtility]::HtmlEncode(
                        [string]$DataJson
                    )
                }

                if (
                    $Item.PSObject.Properties['Error'] -and
                    $null -ne $Item.Error
                ) {
                    $ErrorText = [System.Net.WebUtility]::HtmlEncode(
                        [string]$Item.Error
                    )
                }

                [void]$InventoryRows.AppendLine(
                    "<tr><td>$ComputerName</td><td>$Collector</td><td>$Status</td><td>$ReadOnly</td><td><pre>$DataText</pre></td><td>$ErrorText</td></tr>"
                )
            }

            if ($InventoryRows.Length -eq 0) {
                [void]$InventoryRows.AppendLine(
                    '<tr><td colspan="6">No inventory records.</td></tr>'
                )
            }

            # ------------------------------------------------------------
            # HTML document
            # ------------------------------------------------------------

            $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>TechHub Active Directory Assessment</title>

<style>

body {
    font-family: Arial, Helvetica, sans-serif;
    margin: 40px;
    background: #f5f5f5;
    color: #222;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: #fff;
    padding: 32px;
}

h1 {
    margin-top: 0;
}

h2 {
    margin-top: 32px;
}

.metadata {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 24px;
}

.card {
    border: 1px solid #ddd;
    padding: 12px;
    background: #fafafa;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}

th,
td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}

th {
    background: #eee;
}

pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: Consolas, monospace;
    font-size: 12px;
}

.footer {
    margin-top: 32px;
    font-size: 12px;
    color: #666;
}

</style>

</head>

<body>

<div class="container">

<h1>TechHub Active Directory Assessment</h1>

<div class="metadata">

    <div class="card">
        <strong>Assessment ID</strong><br>
        $AssessmentId
    </div>

    <div class="card">
        <strong>Provider Status</strong><br>
        $ProviderStatus
    </div>

    <div class="card">
        <strong>Data Availability</strong><br>
        $DataAvailability
    </div>

    <div class="card">
        <strong>Started At</strong><br>
        $StartedAt
    </div>

    <div class="card">
        <strong>Completed At</strong><br>
        $CompletedAt
    </div>

    <div class="card">
        <strong>Read-only Assessment</strong><br>
        True
    </div>

</div>

<h2>Summary</h2>

<table>

<thead>

<tr>
    <th>Metric</th>
    <th>Count</th>
</tr>

</thead>

<tbody>

<tr>
    <td>Findings</td>
    <td>$($Assessment.Summary.FindingsCount)</td>
</tr>

<tr>
    <td>Observations</td>
    <td>$($Assessment.Summary.ObservationsCount)</td>
</tr>

<tr>
    <td>Inventory</td>
    <td>$($Assessment.Summary.InventoryCount)</td>
</tr>

<tr>
    <td>Health</td>
    <td>$($Assessment.Summary.HealthCount)</td>
</tr>

<tr>
    <td>Provider Results</td>
    <td>$($Assessment.Summary.ProviderResultsCount)</td>
</tr>

</tbody>

</table>

<h2>Findings</h2>

<table>

<thead>

<tr>
    <th>Check ID</th>
    <th>Title</th>
    <th>Severity</th>
    <th>Status</th>
    <th>Read Only</th>
</tr>

</thead>

<tbody>

$FindingRows

</tbody>

</table>

<h2>Inventory</h2>

<table>

<thead>

<tr>
    <th>Computer</th>
    <th>Collector</th>
    <th>Status</th>
    <th>Read Only</th>
    <th>Data</th>
    <th>Error</th>
</tr>

</thead>

<tbody>

$InventoryRows

</tbody>

</table>

<div class="footer">

    Generated by TechHub.ActiveDirectory.<br>
    Assessment operations are read-only.

</div>

</div>

</body>
</html>
"@

            # ------------------------------------------------------------
            # Write file
            # ------------------------------------------------------------

            [System.IO.File]::WriteAllText(
                $Path,
                $Html,
                [System.Text.UTF8Encoding]::new($false)
            )

            Get-Item -LiteralPath $Path
        }
        catch {
            throw "Unable to export TechHub AD assessment to HTML: $($_.Exception.Message)"
        }
    }
}