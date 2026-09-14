#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentHtml {
    <#
    .SYNOPSIS
        Exports assessment/collector results to a readable HTML report.

    .DESCRIPTION
        Accepts the flat array of objects returned by Invoke-AssessmentADAssessment,
        Invoke-AssessmentADRemoteAssessment, or any individual Get-AssessmentAD*
        function. Records are grouped by their CheckId or Collector property
        (falling back to a single "Results" group), and each record is rendered
        as a card listing every property. No assumption is made about the object
        shape, so the same exporter works for every check and collector.

    .PARAMETER InputObject
        The records to export. Accepts pipeline input.

    .PARAMETER Path
        Destination HTML file.

    .PARAMETER Title
        Optional report title. Defaults to "Active Directory Assessment".

    .OUTPUTS
        The written file (Get-Item).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$Title = 'Active Directory Assessment'
    )

    begin {
        $AllRecords = New-Object System.Collections.Generic.List[object]
    }

    process {
        if ($null -ne $InputObject) {
            $AllRecords.Add($InputObject)
        }
    }

    end {
        try {

            function ConvertTo-HtmlSafe {
                param([AllowNull()][object]$Value)
                if ($null -eq $Value) { return '' }
                [System.Net.WebUtility]::HtmlEncode([string]$Value)
            }

            function ConvertTo-HtmlValueList {
                param([AllowNull()][object]$Value)

                if ($null -eq $Value) { return '<span class="subtle">&mdash;</span>' }

                $IsScalar = $Value -is [string] -or $Value -is [bool] -or $Value -is [datetime] -or $Value -is [guid] -or $Value.GetType().IsPrimitive

                if ($IsScalar) {
                    $Text = [string]$Value
                    if ([string]::IsNullOrWhiteSpace($Text)) { return '<span class="subtle">&mdash;</span>' }
                    return ConvertTo-HtmlSafe $Text
                }

                if ($Value -is [System.Collections.IEnumerable]) {
                    $Items = @($Value)
                    if ($Items.Count -eq 0) { return '<span class="subtle">None</span>' }
                    $ListItems = foreach ($Item in $Items) { '<li>' + (ConvertTo-HtmlValueList $Item) + '</li>' }
                    return '<ul class="value-list">' + ($ListItems -join '') + '</ul>'
                }

                if ($null -ne $Value.PSObject -and $Value.PSObject.Properties.Count -gt 0) {
                    $Rows = foreach ($Property in $Value.PSObject.Properties) {
                        '<li><strong>' + (ConvertTo-HtmlSafe $Property.Name) + ':</strong> ' + (ConvertTo-HtmlValueList $Property.Value) + '</li>'
                    }
                    return '<ul class="value-list">' + ($Rows -join '') + '</ul>'
                }

                return ConvertTo-HtmlSafe ([string]$Value)
            }

            function Get-RecordTitle {
                param([object]$Record)

                foreach ($Candidate in @('Name', 'GroupName', 'MemberName', 'ComputerName', 'ServiceName', 'AppPoolName', 'TaskName', 'ShareName', 'FeatureName', 'AssignmentName', 'ObjectName')) {
                    if ($null -ne $Record.PSObject.Properties[$Candidate]) {
                        $Value = [string]$Record.PSObject.Properties[$Candidate].Value
                        if (-not [string]::IsNullOrWhiteSpace($Value)) { return $Value }
                    }
                }

                return 'Record'
            }

            # ----------------------------------------------------------------
            # Group records by CheckId, then Collector, then a single bucket
            # ----------------------------------------------------------------

            $Groups = [ordered]@{}

            foreach ($Record in $AllRecords) {

                if ($null -eq $Record) { continue }

                $GroupKey = 'Results'

                if ($null -ne $Record.PSObject.Properties['CheckId'] -and -not [string]::IsNullOrWhiteSpace([string]$Record.CheckId)) {
                    $GroupKey = [string]$Record.CheckId
                }
                elseif ($null -ne $Record.PSObject.Properties['Collector'] -and -not [string]::IsNullOrWhiteSpace([string]$Record.Collector)) {
                    $GroupKey = [string]$Record.Collector
                }

                if (-not $Groups.Contains($GroupKey)) {
                    $Groups[$GroupKey] = New-Object System.Collections.Generic.List[object]
                }

                $Groups[$GroupKey].Add($Record)
            }

            # ----------------------------------------------------------------
            # Domain shown in the header, if any record carries one
            # ----------------------------------------------------------------

            $HeaderDomain = $null

            foreach ($Record in $AllRecords) {
                if ($null -ne $Record.PSObject.Properties['Domain'] -and -not [string]::IsNullOrWhiteSpace([string]$Record.Domain)) {
                    $HeaderDomain = [string]$Record.Domain
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($HeaderDomain)) { $HeaderDomain = $Title }

            # ----------------------------------------------------------------
            # Build the sections
            # ----------------------------------------------------------------

            $SectionsHtml = New-Object System.Text.StringBuilder

            if ($Groups.Count -eq 0) {

                [void]$SectionsHtml.AppendLine('<div class="empty-state"><strong>No records were returned.</strong></div>')
            }
            else {

                foreach ($GroupKey in $Groups.Keys) {

                    $Records = $Groups[$GroupKey]

                    [void]$SectionsHtml.AppendLine("<section class=`"group`">")
                    [void]$SectionsHtml.AppendLine("<h2 class=`"group-title`">" + (ConvertTo-HtmlSafe $GroupKey) + " <span class=`"count`">(" + $Records.Count + ")</span></h2>")
                    [void]$SectionsHtml.AppendLine('<div class="record-list">')

                    foreach ($Record in $Records) {

                        $RecordTitle = ConvertTo-HtmlSafe (Get-RecordTitle -Record $Record)

                        [void]$SectionsHtml.AppendLine('<div class="record-card">')
                        [void]$SectionsHtml.AppendLine('<div class="record-card-title">' + $RecordTitle + '</div>')
                        [void]$SectionsHtml.AppendLine('<table class="record-table">')

                        foreach ($Property in $Record.PSObject.Properties) {

                            if ($Property.Name -eq 'IsReadOnly') { continue }

                            [void]$SectionsHtml.AppendLine('<tr><th>' + (ConvertTo-HtmlSafe $Property.Name) + '</th><td>' + (ConvertTo-HtmlValueList $Property.Value) + '</td></tr>')
                        }

                        [void]$SectionsHtml.AppendLine('</table>')
                        [void]$SectionsHtml.AppendLine('</div>')
                    }

                    [void]$SectionsHtml.AppendLine('</div>')
                    [void]$SectionsHtml.AppendLine('</section>')
                }
            }

            $GeneratedAt = ConvertTo-HtmlSafe ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC')
            $HtmlTitle = ConvertTo-HtmlSafe $Title
            $HtmlDomain = ConvertTo-HtmlSafe $HeaderDomain
            $RecordCount = $AllRecords.Count

            $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$HtmlTitle</title>
<style>
:root {
    --navy: #14213d;
    --navy-dark: #0d172b;
    --blue: #2563eb;
    --gray-50: #f8fafc;
    --gray-100: #f1f5f9;
    --gray-200: #e2e8f0;
    --gray-500: #64748b;
    --gray-600: #475569;
    --gray-700: #334155;
    --gray-900: #0f172a;
    --white: #ffffff;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #eef2f7;
    color: var(--gray-900);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.55;
}
.page { max-width: 1200px; margin: 0 auto; padding: 32px; }
.report { background: var(--white); border-radius: 10px; box-shadow: 0 4px 16px rgba(15,23,42,.08); overflow: hidden; }
.header { background: linear-gradient(135deg, var(--navy-dark), var(--navy)); color: var(--white); padding: 30px 36px; }
.header .brand-name { font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; opacity: .72; }
.header h1 { margin: 10px 0 4px; font-size: 26px; }
.header .subtitle { margin: 0; color: #cbd5e1; font-size: 13px; }
.content { padding: 30px 36px 40px; }
.group { margin-top: 32px; }
.group:first-child { margin-top: 0; }
.group-title { font-size: 18px; margin: 0 0 14px; color: var(--gray-900); }
.group-title .count { color: var(--gray-500); font-weight: 400; font-size: 14px; }
.record-list { display: flex; flex-direction: column; gap: 12px; }
.record-card { border: 1px solid var(--gray-200); border-radius: 9px; background: var(--white); overflow: hidden; }
.record-card-title { padding: 12px 16px; background: var(--gray-50); border-bottom: 1px solid var(--gray-200); font-weight: 700; font-size: 14px; }
.record-table { width: 100%; border-collapse: collapse; }
.record-table th { width: 220px; padding: 8px 16px; text-align: left; vertical-align: top; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; color: var(--gray-500); border: 0; }
.record-table td { padding: 8px 16px 8px 0; vertical-align: top; color: var(--gray-700); border: 0; overflow-wrap: anywhere; }
.record-table tr:nth-child(even) { background: var(--gray-50); }
.value-list { margin: 0; padding-left: 16px; font-size: 12.5px; }
.value-list .value-list { margin-top: 3px; color: var(--gray-600); font-size: 11.5px; }
.subtle { color: var(--gray-500); }
.empty-state { padding: 30px; text-align: center; color: var(--gray-500); }
.footer { margin-top: 34px; padding-top: 16px; border-top: 1px solid var(--gray-200); color: var(--gray-500); font-size: 11px; }
@media print { body { background: white; } .page { padding: 0; } .report { box-shadow: none; border-radius: 0; } }
</style>
</head>
<body>
<div class="page">
<div class="report">
<header class="header">
    <div class="brand-name">Assessment.ActiveDirectory</div>
    <h1>$HtmlDomain</h1>
    <p class="subtitle">$RecordCount record(s) &middot; generated $GeneratedAt</p>
</header>
<div class="content">
$($SectionsHtml.ToString())
<div class="footer">Read-only assessment &middot; no Active Directory modifications performed</div>
</div>
</div>
</div>
</body>
</html>
"@

            $Directory = Split-Path -Path $Path -Parent

            if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -LiteralPath $Directory)) {
                New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            [System.IO.File]::WriteAllText($Path, $Html, [System.Text.UTF8Encoding]::new($false))

            Get-Item -LiteralPath $Path
        }
        catch {
            throw "Unable to export to HTML: $($_.Exception.Message)"
        }
    }
}
