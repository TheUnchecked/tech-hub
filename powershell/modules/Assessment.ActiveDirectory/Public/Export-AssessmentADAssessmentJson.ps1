#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentJson {
    <#
    .SYNOPSIS
        Exports assessment/collector results to a JSON file.

    .DESCRIPTION
        Accepts the flat array of objects returned by Invoke-AssessmentADAssessment,
        Invoke-AssessmentADRemoteAssessment, or any individual Get-AssessmentAD*
        function, and serializes it to JSON. No assumption is made about the
        object shape.

    .PARAMETER InputObject
        The records to export. Accepts pipeline input.

    .PARAMETER Path
        Destination file. If omitted, the JSON text is returned instead of written to disk.

    .PARAMETER Depth
        Serialization depth (1-100, default 20).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$Depth = 20
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
            $Json = $AllRecords | ConvertTo-Json -Depth $Depth -ErrorAction Stop

            if ([string]::IsNullOrWhiteSpace($Path)) {
                return $Json
            }

            $Directory = Split-Path -Path $Path -Parent

            if (-not [string]::IsNullOrWhiteSpace($Directory) -and -not (Test-Path -LiteralPath $Directory)) {
                New-Item -Path $Directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            [System.IO.File]::WriteAllText($Path, $Json, [System.Text.UTF8Encoding]::new($false))

            Get-Item -LiteralPath $Path
        }
        catch {
            throw "Unable to export to JSON: $($_.Exception.Message)"
        }
    }
}
