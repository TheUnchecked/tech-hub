#Requires -Version 5.1

Set-StrictMode -Version Latest

function Export-AssessmentADAssessmentCsv {
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
            throw 'The supplied object is not a valid AssessmentADAssessmentResult.'
        }

        try {

            # ============================================================
            # CSV DATASET
            # ============================================================
            #
            # The CSV is designed as a flat, analysis-friendly dataset.
            #
            # One row = one meaningful assessment record.
            #
            # Record types:
            #   Finding
            #   Inventory
            #   Observation
            #   ProviderResult
            #   CheckResult
            #   Assessment
            #
            # The Assessment record is emitted only when the assessment
            # contains no other records.
            #
            # This makes the CSV suitable for:
            #   - Microsoft Excel
            #   - Power Query
            #   - Power BI
            #   - Pivot Tables
            #   - ETL / data processing
            #
            # ============================================================

            $Rows = [System.Collections.Generic.List[object]]::new()

            # ============================================================
            # COMMON VALUES
            # ============================================================

            $AssessmentId = $Assessment.AssessmentId

            $Domain = $null
            $Forest = $null
            $DomainController = $null
            $ProviderStatus = $null
            $DataAvailability = $null

            if ($Assessment.PSObject.Properties['Domain']) {
                $Domain = $Assessment.Domain
            }

            if ($Assessment.PSObject.Properties['Forest']) {
                $Forest = $Assessment.Forest
            }

            if ($Assessment.PSObject.Properties['DomainController']) {
                $DomainController = $Assessment.DomainController
            }

            if ($Assessment.PSObject.Properties['ProviderStatus']) {
                $ProviderStatus = $Assessment.ProviderStatus
            }

            if ($Assessment.PSObject.Properties['DataAvailability']) {
                $DataAvailability = $Assessment.DataAvailability
            }

            # ============================================================
            # FINDINGS
            # ============================================================

            foreach ($Finding in @($Assessment.Findings)) {

                if ($null -eq $Finding) {
                    continue
                }

                $Rows.Add(
                    [PSCustomObject][ordered]@{

                        AssessmentId = $AssessmentId
                        RecordType   = 'Finding'

                        Domain           = if ($Finding.PSObject.Properties['Domain']) {
                            $Finding.Domain
                        }
                        else {
                            $Domain
                        }

                        Forest           = if ($Finding.PSObject.Properties['Forest']) {
                            $Finding.Forest
                        }
                        else {
                            $Forest
                        }

                        DomainController = if ($Finding.PSObject.Properties['DomainController']) {
                            $Finding.DomainController
                        }
                        else {
                            $DomainController
                        }

                        ComputerName = if ($Finding.PSObject.Properties['ComputerName']) {
                            $Finding.ComputerName
                        }
                        else {
                            $null
                        }

                        Collector = $null

                        CheckId = if ($Finding.PSObject.Properties['CheckId']) {
                            $Finding.CheckId
                        }
                        else {
                            $null
                        }

                        CheckName = if ($Finding.PSObject.Properties['CheckName']) {
                            $Finding.CheckName
                        }
                        else {
                            $null
                        }

                        FindingId = if ($Finding.PSObject.Properties['FindingId']) {
                            $Finding.FindingId
                        }
                        else {
                            $null
                        }

                        Title = if ($Finding.PSObject.Properties['Title']) {
                            $Finding.Title
                        }
                        else {
                            $null
                        }

                        Description = if ($Finding.PSObject.Properties['Description']) {
                            $Finding.Description
                        }
                        else {
                            $null
                        }

                        Category = if ($Finding.PSObject.Properties['Category']) {
                            $Finding.Category
                        }
                        else {
                            $null
                        }

                        Severity = if ($Finding.PSObject.Properties['Severity']) {
                            $Finding.Severity
                        }
                        else {
                            $null
                        }

                        Confidence = if ($Finding.PSObject.Properties['Confidence']) {
                            $Finding.Confidence
                        }
                        else {
                            $null
                        }

                        Status = if ($Finding.PSObject.Properties['Status']) {
                            $Finding.Status
                        }
                        else {
                            $null
                        }

                        ObjectType = if ($Finding.PSObject.Properties['ObjectType']) {
                            $Finding.ObjectType
                        }
                        else {
                            $null
                        }

                        DistinguishedName = if ($Finding.PSObject.Properties['DistinguishedName']) {
                            $Finding.DistinguishedName
                        }
                        else {
                            $null
                        }

                        SamAccountName = if ($Finding.PSObject.Properties['SamAccountName']) {
                            $Finding.SamAccountName
                        }
                        else {
                            $null
                        }

                        ObjectGuid = if ($Finding.PSObject.Properties['ObjectGuid']) {
                            $Finding.ObjectGuid
                        }
                        else {
                            $null
                        }

                        AffectedObject = if ($Finding.PSObject.Properties['AffectedObject']) {
                            $Finding.AffectedObject |
                                ConvertTo-Json -Depth 10 -Compress
                        }
                        else {
                            $null
                        }

                        Evidence = if ($Finding.PSObject.Properties['Evidence']) {
                            $Finding.Evidence |
                                ConvertTo-Json -Depth 10 -Compress
                        }
                        else {
                            $null
                        }

                        Risk = if ($Finding.PSObject.Properties['Risk']) {
                            $Finding.Risk
                        }
                        else {
                            $null
                        }

                        Recommendation = if ($Finding.PSObject.Properties['Recommendation']) {
                            $Finding.Recommendation
                        }
                        else {
                            $null
                        }

                        References = if ($Finding.PSObject.Properties['References']) {
                            @($Finding.References) -join ' | '
                        }
                        else {
                            $null
                        }

                        CollectedAt = if ($Finding.PSObject.Properties['CollectedAt']) {
                            $Finding.CollectedAt
                        }
                        else {
                            $null
                        }

                        IsReadOnly = if ($Finding.PSObject.Properties['IsReadOnly']) {
                            $Finding.IsReadOnly
                        }
                        else {
                            $true
                        }

                        ProviderStatus   = $ProviderStatus
                        DataAvailability = $DataAvailability

                        Data = $null
                        Error = $null
                    }
                )
            }

            # ============================================================
            # INVENTORY
            # ============================================================

            foreach ($InventoryItem in @($Assessment.Inventory)) {

                if ($null -eq $InventoryItem) {
                    continue
                }

                $DataJson = $null

                if ($InventoryItem.PSObject.Properties['Data']) {
                    $DataJson = $InventoryItem.Data |
                        ConvertTo-Json -Depth 12 -Compress
                }

                $Rows.Add(
                    [PSCustomObject][ordered]@{

                        AssessmentId = $AssessmentId
                        RecordType   = 'Inventory'

                        Domain           = $Domain
                        Forest           = $Forest
                        DomainController = $DomainController

                        ComputerName = if ($InventoryItem.PSObject.Properties['ComputerName']) {
                            $InventoryItem.ComputerName
                        }
                        else {
                            $null
                        }

                        Collector = if ($InventoryItem.PSObject.Properties['Collector']) {
                            $InventoryItem.Collector
                        }
                        else {
                            $null
                        }

                        CheckId      = $null
                        CheckName    = $null
                        FindingId    = $null
                        Title        = $null
                        Description  = $null
                        Category     = $null
                        Severity     = $null
                        Confidence   = $null

                        Status = if ($InventoryItem.PSObject.Properties['Status']) {
                            $InventoryItem.Status
                        }
                        else {
                            $null
                        }

                        ObjectType        = $null
                        DistinguishedName = $null
                        SamAccountName    = $null
                        ObjectGuid        = $null
                        AffectedObject    = $null
                        Evidence          = $null
                        Risk              = $null
                        Recommendation    = $null
                        References        = $null
                        CollectedAt       = $null

                        IsReadOnly = if ($InventoryItem.PSObject.Properties['IsReadOnly']) {
                            $InventoryItem.IsReadOnly
                        }
                        else {
                            $true
                        }

                        ProviderStatus   = $ProviderStatus
                        DataAvailability = $DataAvailability

                        Data = $DataJson

                        Error = if ($InventoryItem.PSObject.Properties['Error']) {
                            $InventoryItem.Error
                        }
                        else {
                            $null
                        }
                    }
                )
            }

            # ============================================================
            # OBSERVATIONS
            # ============================================================

            foreach ($Observation in @($Assessment.Observations)) {

                if ($null -eq $Observation) {
                    continue
                }

                $ObservationJson =
                    $Observation |
                    ConvertTo-Json -Depth 12 -Compress

                $Rows.Add(
                    [PSCustomObject][ordered]@{

                        AssessmentId = $AssessmentId
                        RecordType   = 'Observation'

                        Domain           = $Domain
                        Forest           = $Forest
                        DomainController = $DomainController

                        ComputerName = if ($Observation.PSObject.Properties['ComputerName']) {
                            $Observation.ComputerName
                        }
                        else {
                            $null
                        }

                        Collector = if ($Observation.PSObject.Properties['Collector']) {
                            $Observation.Collector
                        }
                        else {
                            $null
                        }

                        CheckId = if ($Observation.PSObject.Properties['CheckId']) {
                            $Observation.CheckId
                        }
                        else {
                            $null
                        }

                        CheckName = if ($Observation.PSObject.Properties['CheckName']) {
                            $Observation.CheckName
                        }
                        else {
                            $null
                        }

                        FindingId    = $null

                        Title = if ($Observation.PSObject.Properties['Title']) {
                            $Observation.Title
                        }
                        else {
                            $null
                        }

                        Description = if ($Observation.PSObject.Properties['Description']) {
                            $Observation.Description
                        }
                        else {
                            $null
                        }

                        Category = if ($Observation.PSObject.Properties['Category']) {
                            $Observation.Category
                        }
                        else {
                            $null
                        }

                        Severity = if ($Observation.PSObject.Properties['Severity']) {
                            $Observation.Severity
                        }
                        else {
                            $null
                        }

                        Confidence = if ($Observation.PSObject.Properties['Confidence']) {
                            $Observation.Confidence
                        }
                        else {
                            $null
                        }

                        Status = if ($Observation.PSObject.Properties['Status']) {
                            $Observation.Status
                        }
                        else {
                            $null
                        }

                        ObjectType        = $null
                        DistinguishedName = $null
                        SamAccountName    = $null
                        ObjectGuid        = $null
                        AffectedObject    = $null
                        Evidence          = $null
                        Risk              = $null
                        Recommendation    = $null
                        References        = $null
                        CollectedAt       = $null

                        IsReadOnly = if ($Observation.PSObject.Properties['IsReadOnly']) {
                            $Observation.IsReadOnly
                        }
                        else {
                            $true
                        }

                        ProviderStatus   = $ProviderStatus
                        DataAvailability = $DataAvailability

                        Data = $ObservationJson
                        Error = $null
                    }
                )
            }

            # ============================================================
            # PROVIDER RESULTS
            # ============================================================

            foreach ($ProviderResult in @($Assessment.ProviderResults)) {

                if ($null -eq $ProviderResult) {
                    continue
                }

                $ProviderData = $null

                if ($ProviderResult.PSObject.Properties['Data']) {
                    $ProviderData =
                        $ProviderResult.Data |
                        ConvertTo-Json -Depth 12 -Compress
                }

                $Rows.Add(
                    [PSCustomObject][ordered]@{

                        AssessmentId = $AssessmentId
                        RecordType   = 'ProviderResult'

                        Domain           = $Domain
                        Forest           = $Forest
                        DomainController = $DomainController

                        ComputerName = if ($ProviderResult.PSObject.Properties['ComputerName']) {
                            $ProviderResult.ComputerName
                        }
                        else {
                            $null
                        }

                        Collector = if ($ProviderResult.PSObject.Properties['Provider']) {
                            $ProviderResult.Provider
                        }
                        else {
                            'AssessmentADProvider'
                        }

                        CheckId      = $null
                        CheckName    = $null
                        FindingId    = $null
                        Title        = $null
                        Description  = $null
                        Category     = $null
                        Severity     = $null
                        Confidence   = $null
                        Status       = if ($ProviderResult.PSObject.Properties['Status']) {
                            $ProviderResult.Status
                        }
                        else {
                            $null
                        }

                        ObjectType        = $null
                        DistinguishedName = $null
                        SamAccountName    = $null
                        ObjectGuid        = $null
                        AffectedObject    = $null
                        Evidence          = $null
                        Risk              = $null
                        Recommendation    = $null
                        References        = $null
                        CollectedAt       = $null

                        IsReadOnly = if ($ProviderResult.PSObject.Properties['IsReadOnly']) {
                            $ProviderResult.IsReadOnly
                        }
                        else {
                            $true
                        }

                        ProviderStatus   = $ProviderStatus
                        DataAvailability = $DataAvailability

                        Data = $ProviderData

                        Error = if ($ProviderResult.PSObject.Properties['ErrorMessage']) {
                            $ProviderResult.ErrorMessage
                        }
                        else {
                            $null
                        }
                    }
                )
            }

            # ============================================================
            # CHECK EXECUTION RESULTS
            # ============================================================

            if (
                $Assessment.PSObject.Properties['Metadata'] -and
                $null -ne $Assessment.Metadata -and
                $Assessment.Metadata.PSObject.Properties['CheckResults']
            ) {

                foreach ($CheckResult in @($Assessment.Metadata.CheckResults)) {

                    if ($null -eq $CheckResult) {
                        continue
                    }

                    $Rows.Add(
                        [PSCustomObject][ordered]@{

                            AssessmentId = $AssessmentId
                            RecordType   = 'CheckResult'

                            Domain           = $Domain
                            Forest           = $Forest
                            DomainController = $DomainController

                            ComputerName = $null
                            Collector    = 'AssessmentEngine'

                            CheckId = if ($CheckResult.PSObject.Properties['CheckId']) {
                                $CheckResult.CheckId
                            }
                            else {
                                $null
                            }

                            CheckName = if ($CheckResult.PSObject.Properties['CheckName']) {
                                $CheckResult.CheckName
                            }
                            else {
                                $null
                            }

                            FindingId   = $null
                            Title       = $null
                            Description = $null
                            Category    = $null
                            Severity    = $null
                            Confidence  = $null

                            Status = if ($CheckResult.PSObject.Properties['Status']) {
                                $CheckResult.Status
                            }
                            else {
                                $null
                            }

                            ObjectType        = $null
                            DistinguishedName = $null
                            SamAccountName    = $null
                            ObjectGuid        = $null
                            AffectedObject    = $null
                            Evidence          = $null
                            Risk              = $null
                            Recommendation    = $null
                            References        = $null
                            CollectedAt       = $null

                            IsReadOnly = if ($CheckResult.PSObject.Properties['IsReadOnly']) {
                                $CheckResult.IsReadOnly
                            }
                            else {
                                $true
                            }

                            ProviderStatus   = $ProviderStatus
                            DataAvailability = $DataAvailability

                            Data = $CheckResult |
                                ConvertTo-Json -Depth 12 -Compress

                            Error = if ($CheckResult.PSObject.Properties['ErrorMessage']) {
                                $CheckResult.ErrorMessage
                            }
                            else {
                                $null
                            }
                        }
                    )
                }
            }

            # ============================================================
            # EMPTY ASSESSMENT FALLBACK
            # ============================================================

            if ($Rows.Count -eq 0) {

                $Rows.Add(
                    [PSCustomObject][ordered]@{

                        AssessmentId = $AssessmentId
                        RecordType   = 'Assessment'

                        Domain           = $Domain
                        Forest           = $Forest
                        DomainController = $DomainController

                        ComputerName = $null
                        Collector    = 'AssessmentEngine'

                        CheckId      = $null
                        CheckName    = $null
                        FindingId    = $null
                        Title        = 'Active Directory Assessment'
                        Description  = 'Assessment completed without findings, inventory records, observations, provider results or check execution results.'
                        Category     = 'Assessment'
                        Severity     = $null
                        Confidence   = $null

                        Status = $DataAvailability

                        ObjectType        = $null
                        DistinguishedName = $null
                        SamAccountName    = $null
                        ObjectGuid        = $null
                        AffectedObject    = $null
                        Evidence          = $null
                        Risk              = $null
                        Recommendation    = $null
                        References        = $null
                        CollectedAt       = $Assessment.CompletedAt

                        IsReadOnly = $true

                        ProviderStatus   = $ProviderStatus
                        DataAvailability = $DataAvailability

                        Data = $null
                        Error = $null
                    }
                )
            }

            # ============================================================
            # OUTPUT DIRECTORY
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
            # EXPORT
            # ============================================================

            $Rows |
                Export-Csv `
                    -LiteralPath $Path `
                    -NoTypeInformation `
                    -Encoding UTF8 `
                    -Force `
                    -ErrorAction Stop

            # Return the generated file.
            Get-Item -LiteralPath $Path
        }
        catch {

            throw `
                "Unable to export Assessment AD assessment to CSV: $($_.Exception.Message)"
        }
    }
}