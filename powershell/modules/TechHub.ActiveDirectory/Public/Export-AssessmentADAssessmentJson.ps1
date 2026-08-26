#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentJson {

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

            # ============================================================
            # ASSESSMENT ID
            # ============================================================

            $AssessmentId = [string]$Assessment.AssessmentId


            # ============================================================
            # METADATA
            # ============================================================

            $Metadata = [ordered]@{}

            if ($null -ne $Assessment.PSObject.Properties['Metadata']) {

                foreach ($Property in $Assessment.Metadata.PSObject.Properties) {

                    $Metadata[$Property.Name] = $Property.Value
                }
            }

            # Always guarantee AssessmentId in metadata.
            $Metadata['AssessmentId'] = $Assessment.AssessmentId


            # ============================================================
            # SUMMARY
            # ============================================================

            $Summary = [ordered]@{}

            if ($null -ne $Assessment.PSObject.Properties['Summary']) {

                foreach ($Property in $Assessment.Summary.PSObject.Properties) {

                    $Summary[$Property.Name] = $Property.Value
                }
            }


            # ============================================================
            # EXECUTION INFORMATION
            # ============================================================

            $Execution = [ordered]@{

                StartedAt   = $null
                CompletedAt = $null
                Duration    = $null

                ProviderStatus  = $null
                DataAvailability = $null

                IsReadOnly = $true
            }

            if ($null -ne $Assessment.PSObject.Properties['StartedAt']) {
                $Execution.StartedAt = $Assessment.StartedAt
            }

            if ($null -ne $Assessment.PSObject.Properties['CompletedAt']) {
                $Execution.CompletedAt = $Assessment.CompletedAt
            }

            if ($null -ne $Assessment.PSObject.Properties['Duration']) {
                $Execution.Duration = $Assessment.Duration
            }

            if ($null -ne $Assessment.PSObject.Properties['ProviderStatus']) {
                $Execution.ProviderStatus = $Assessment.ProviderStatus
            }

            if ($null -ne $Assessment.PSObject.Properties['DataAvailability']) {
                $Execution.DataAvailability = $Assessment.DataAvailability
            }


            # ============================================================
            # FINDINGS
            # ============================================================

            $Findings = @()

            if ($null -ne $Assessment.PSObject.Properties['Findings']) {

                $Findings = @($Assessment.Findings)
            }


            # ============================================================
            # OBSERVATIONS
            # ============================================================

            $Observations = @()

            if ($null -ne $Assessment.PSObject.Properties['Observations']) {

                $Observations = @($Assessment.Observations)
            }


            # ============================================================
            # INVENTORY
            # ============================================================

            $Inventory = @()

            if ($null -ne $Assessment.PSObject.Properties['Inventory']) {

                $Inventory = @($Assessment.Inventory)
            }


            # ============================================================
            # HEALTH
            # ============================================================

            $Health = @()

            if ($null -ne $Assessment.PSObject.Properties['Health']) {

                $Health = @($Assessment.Health)
            }


            # ============================================================
            # PROVIDER RESULTS
            # ============================================================

            $ProviderResults = @()

            if ($null -ne $Assessment.PSObject.Properties['ProviderResults']) {

                $ProviderResults = @($Assessment.ProviderResults)
            }


            # ============================================================
            # JSON DOCUMENT
            # ============================================================
            #
            # AssessmentId is deliberately exposed at the ROOT level.
            #
            # This preserves compatibility with existing consumers:
            #
            #     $Object.AssessmentId
            #
            # while the structured Assessment.Metadata section remains
            # available for reporting and Power BI ingestion.
            #
            # ============================================================

            $Document = [ordered]@{

                SchemaVersion = '1.0'

                AssessmentId = $AssessmentId

                Exporter = [ordered]@{

                    Name       = 'TechHub.ActiveDirectory'
                    Format     = 'JSON'
                    Purpose    = 'Active Directory security assessment export'
                    IsReadOnly = $true
                }

                Assessment = [ordered]@{

                    Metadata = [PSCustomObject]$Metadata

                    Summary = [PSCustomObject]$Summary
                }

                Findings = @(
                    $Findings
                )

                Observations = @(
                    $Observations
                )

                Inventory = @(
                    $Inventory
                )

                Health = @(
                    $Health
                )

                ProviderResults = @(
                    $ProviderResults
                )

                Execution = [PSCustomObject]$Execution
            }


            # ============================================================
            # SERIALIZE
            # ============================================================

            $Json = $Document |
                ConvertTo-Json `
                    -Depth $Depth `
                    -Compress:$false `
                    -ErrorAction Stop


            # ============================================================
            # FILE OUTPUT
            # ============================================================

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