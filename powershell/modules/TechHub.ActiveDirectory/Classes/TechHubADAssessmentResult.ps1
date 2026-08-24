class TechHubADAssessmentResult {
    [object]$Metadata
    [object]$Summary

    [System.Collections.ArrayList]$Findings
    [System.Collections.ArrayList]$Observations
    [System.Collections.ArrayList]$Inventory
    [System.Collections.ArrayList]$Health
    [System.Collections.ArrayList]$ProviderResults

    [Guid]$AssessmentId

    [Nullable[datetime]]$StartedAt
    [Nullable[datetime]]$CompletedAt
    [Nullable[timespan]]$Duration

    [string]$Domain
    [string]$Forest
    [string]$DomainController
    [string]$ResultType
    [string]$ProviderStatus
    [string]$DataAvailability

    TechHubADAssessmentResult() {
        $this.AssessmentId = [guid]::NewGuid()
        $this.StartedAt = (Get-Date).ToUniversalTime()
        $this.CompletedAt = $null
        $this.Duration = $null

        $this.Metadata = [PSCustomObject][ordered]@{
            AssessmentId = $this.AssessmentId
            StartedAt    = $this.StartedAt
        }

        $this.Summary = [PSCustomObject][ordered]@{
            FindingsCount        = 0
            ObservationsCount    = 0
            InventoryCount       = 0
            HealthCount          = 0
            ProviderResultsCount = 0
            SeverityCounts       = [ordered]@{}
        }

        $this.Findings = New-Object System.Collections.ArrayList
        $this.Observations = New-Object System.Collections.ArrayList
        $this.Inventory = New-Object System.Collections.ArrayList
        $this.Health = New-Object System.Collections.ArrayList
        $this.ProviderResults = New-Object System.Collections.ArrayList

        $this.ProviderStatus = $null
        $this.DataAvailability = $null
    }

    [void] AddFinding([object]$Finding) {
        if ($null -eq $Finding) {
            throw 'Finding cannot be null.'
        }

        [void]$this.Findings.Add($Finding)
        $this.Summary.FindingsCount = $this.Findings.Count

        $Severity = $null

        if ($null -ne $Finding.PSObject.Properties['Severity']) {
            $Severity = [string]$Finding.PSObject.Properties['Severity'].Value
        }

        if (-not [string]::IsNullOrWhiteSpace($Severity)) {
            if (-not $this.Summary.SeverityCounts.Contains($Severity)) {
                $this.Summary.SeverityCounts[$Severity] = 0
            }

            $this.Summary.SeverityCounts[$Severity] =
                [int]$this.Summary.SeverityCounts[$Severity] + 1
        }
    }

    [void] AddObservation([object]$Observation) {
        if ($null -eq $Observation) {
            throw 'Observation cannot be null.'
        }

        [void]$this.Observations.Add($Observation)
        $this.Summary.ObservationsCount = $this.Observations.Count
    }

    [void] AddInventory([object]$InventoryItem) {
        if ($null -eq $InventoryItem) {
            throw 'Inventory item cannot be null.'
        }

        [void]$this.Inventory.Add($InventoryItem)
        $this.Summary.InventoryCount = $this.Inventory.Count
    }

    [void] AddHealth([object]$HealthResult) {
        if ($null -eq $HealthResult) {
            throw 'Health result cannot be null.'
        }

        [void]$this.Health.Add($HealthResult)
        $this.Summary.HealthCount = $this.Health.Count
    }

    [void] AddProviderResult([object]$ProviderResult) {
        if ($null -eq $ProviderResult) {
            throw 'Provider result cannot be null.'
        }

        [void]$this.ProviderResults.Add($ProviderResult)
        $this.Summary.ProviderResultsCount = $this.ProviderResults.Count
    }

    [void] SetProviderStatus([string]$Status) {
        if ($Status -notin @(
            'Available',
            'Partial',
            'NotAvailable',
            'Error'
        )) {
            throw "Unsupported ProviderStatus: $Status"
        }

        $this.ProviderStatus = $Status
    }

    [void] SetDataAvailability([string]$Availability) {
        if ($Availability -notin @(
            'Complete',
            'Partial',
            'NotAvailable'
        )) {
            throw "Unsupported DataAvailability: $Availability"
        }

        $this.DataAvailability = $Availability
    }

    [void] Complete([datetime]$CompletionTime) {
        $this.CompletedAt = $CompletionTime.ToUniversalTime()

        if ($null -ne $this.StartedAt) {
            $Start = [datetime]$this.StartedAt
            $End = [datetime]$this.CompletedAt

            $this.Duration = $End - $Start
        }
    }
}