#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentCsv {
    <#
    .SYNOPSIS
        Exports assessment/collector results to a CSV file.

    .DESCRIPTION
        Accepts the flat array of objects returned by Invoke-AssessmentADAssessment,
        Invoke-AssessmentADRemoteAssessment, or any individual Get-AssessmentAD*
        function. Since different checks/collectors return objects with different
        shapes, the column set is the union of every property seen across all
        records (missing values become empty cells). Array and nested-object
        values are flattened to a readable string instead of PowerShell's default
        "System.Object[]".

    .PARAMETER InputObject
        The records to export. Accepts pipeline input.

    .PARAMETER Path
        Destination CSV file.

    .OUTPUTS
        The written file (Get-Item).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
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

        function ConvertTo-CsvFlatValue {
            param([AllowNull()][object]$Value)

            if ($null -eq $Value) { return $null }

            if ($Value -is [string] -or $Value.GetType().IsPrimitive -or $Value -is [datetime] -or $Value -is [guid]) {
                return [string]$Value
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                return (@($Value) | ForEach-Object { ConvertTo-CsvFlatValue $_ }) -join '; '
            }

            try {
                return ($Value | ConvertTo-Json -Compress -Depth 6)
            }
            catch {
                return [string]$Value
            }
        }

        try {
            if ($AllRecords.Count -eq 0) {
                Write-Verbose 'No records to export.'
                return
            }

            $Directory = Split-Path -Path $Path -Parent

            if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -LiteralPath $Directory)) {
                New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            # ------------------------------------------------------------
            # Union of every property name across all records
            # ------------------------------------------------------------

            $PropertyNames = New-Object System.Collections.Generic.List[string]
            $Seen = @{}

            foreach ($Record in $AllRecords) {
                foreach ($PropertyName in $Record.PSObject.Properties.Name) {
                    if (-not $Seen.ContainsKey($PropertyName)) {
                        $Seen[$PropertyName] = $true
                        $PropertyNames.Add($PropertyName)
                    }
                }
            }

            # ------------------------------------------------------------
            # Normalize every record to the same column set
            # ------------------------------------------------------------

            $NormalizedRows = foreach ($Record in $AllRecords) {

                $Row = [ordered]@{}

                foreach ($PropertyName in $PropertyNames) {

                    $RawValue = $null

                    if ($null -ne $Record.PSObject.Properties[$PropertyName]) {
                        $RawValue = $Record.PSObject.Properties[$PropertyName].Value
                    }

                    $Row[$PropertyName] = ConvertTo-CsvFlatValue $RawValue
                }

                [PSCustomObject]$Row
            }

            $NormalizedRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            Get-Item -LiteralPath $Path
        }
        catch {
            throw "Unable to export to CSV: $($_.Exception.Message)"
        }
    }
}
