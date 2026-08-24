#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-TechHubADAssessmentJson {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )]
        [object]$Assessment,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$Depth = 20
    )

    process {

        if ($null -eq $Assessment) {
            throw 'Assessment cannot be null.'
        }

        if (-not $Assessment.PSObject.Properties['AssessmentId']) {
            throw 'The supplied object is not a valid TechHubADAssessmentResult.'
        }

        try {
            $Json = $Assessment |
                ConvertTo-Json `
                    -Depth $Depth `
                    -Compress:$false `
                    -ErrorAction Stop

            if (-not [string]::IsNullOrWhiteSpace($Path)) {

                $Directory = Split-Path `
                    -Path $Path `
                    -Parent

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

                [System.IO.File]::WriteAllText(
                    $Path,
                    $Json,
                    [System.Text.UTF8Encoding]::new($false)
                )

                Get-Item -LiteralPath $Path
            }
            else {
                $Json
            }
        }
        catch {
            throw "Unable to export TechHub AD assessment to JSON: $($_.Exception.Message)"
        }
    }
}