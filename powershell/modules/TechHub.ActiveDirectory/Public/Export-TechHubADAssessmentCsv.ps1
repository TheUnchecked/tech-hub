#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-TechHubADAssessmentCsv {
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
            $Rows = [System.Collections.Generic.List[object]]::new()

            foreach ($Finding in @($Assessment.Findings)) {
                $Rows.Add(
                    [PSCustomObject][ordered]@{
                        AssessmentId = $Assessment.AssessmentId
                        RecordType   = 'Finding'
                        ComputerName = $null
                        Collector    = $null
                        CheckId      = if ($Finding.PSObject.Properties['CheckId']) { $Finding.CheckId } else { $null }
                        Title        = if ($Finding.PSObject.Properties['Title']) { $Finding.Title } else { $null }
                        Severity     = if ($Finding.PSObject.Properties['Severity']) { $Finding.Severity } else { $null }
                        Status       = if ($Finding.PSObject.Properties['Status']) { $Finding.Status } else { $null }
                        IsReadOnly   = if ($Finding.PSObject.Properties['IsReadOnly']) { $Finding.IsReadOnly } else { $true }
                        Data         = $null
                        Error        = $null
                    }
                )
            }

            foreach ($InventoryItem in @($Assessment.Inventory)) {

                $DataJson = $null

                if ($null -ne $InventoryItem.PSObject.Properties['Data']) {
                    $DataJson = $InventoryItem.Data |
                        ConvertTo-Json -Depth 10 -Compress
                }

                $Rows.Add(
                    [PSCustomObject][ordered]@{
                        AssessmentId = $Assessment.AssessmentId
                        RecordType   = 'Inventory'
                        ComputerName = if ($InventoryItem.PSObject.Properties['ComputerName']) { $InventoryItem.ComputerName } else { $null }
                        Collector    = if ($InventoryItem.PSObject.Properties['Collector']) { $InventoryItem.Collector } else { $null }
                        CheckId      = $null
                        Title        = $null
                        Severity     = $null
                        Status       = if ($InventoryItem.PSObject.Properties['Status']) { $InventoryItem.Status } else { $null }
                        IsReadOnly   = if ($InventoryItem.PSObject.Properties['IsReadOnly']) { $InventoryItem.IsReadOnly } else { $true }
                        Data         = $DataJson
                        Error        = if ($InventoryItem.PSObject.Properties['Error']) { $InventoryItem.Error } else { $null }
                    }
                )
            }

            foreach ($Observation in @($Assessment.Observations)) {
                $Rows.Add(
                    [PSCustomObject][ordered]@{
                        AssessmentId = $Assessment.AssessmentId
                        RecordType   = 'Observation'
                        ComputerName = $null
                        Collector    = $null
                        CheckId      = $null
                        Title        = if ($Observation.PSObject.Properties['Title']) { $Observation.Title } else { $null }
                        Severity     = if ($Observation.PSObject.Properties['Severity']) { $Observation.Severity } else { $null }
                        Status       = if ($Observation.PSObject.Properties['Status']) { $Observation.Status } else { $null }
                        IsReadOnly   = if ($Observation.PSObject.Properties['IsReadOnly']) { $Observation.IsReadOnly } else { $true }
                        Data         = $Observation | ConvertTo-Json -Depth 10 -Compress
                        Error        = $null
                    }
                )
            }

            if ($Rows.Count -eq 0) {
                $Rows.Add(
                    [PSCustomObject][ordered]@{
                        AssessmentId = $Assessment.AssessmentId
                        RecordType   = 'Assessment'
                        ComputerName = $null
                        Collector    = $null
                        CheckId      = $null
                        Title        = $null
                        Severity     = $null
                        Status       = $Assessment.DataAvailability
                        IsReadOnly   = $true
                        Data         = $null
                        Error        = $null
                    }
                )
            }

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

            $Rows |
                Export-Csv `
                    -LiteralPath $Path `
                    -NoTypeInformation `
                    -Encoding UTF8 `
                    -Force `
                    -ErrorAction Stop

            Get-Item -LiteralPath $Path
        }
        catch {
            throw "Unable to export TechHub AD assessment to CSV: $($_.Exception.Message)"
        }
    }
}