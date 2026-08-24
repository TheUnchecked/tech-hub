

Describe 'TechHubADAssessmentResult' {
BeforeAll {
    $TestFile = $PSCommandPath

    if ([string]::IsNullOrWhiteSpace($TestFile)) {
        throw 'Unable to determine test file path.'
    }

    $ModuleRoot = Split-Path -Parent $TestFile
    $ModuleRoot = Split-Path -Parent $ModuleRoot
    $ModuleRoot = Split-Path -Parent $ModuleRoot

    Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'TechHub.ActiveDirectory.psm1') -Force -ErrorAction Stop
}
    AfterAll {
        Remove-Module -Name TechHub.ActiveDirectory -Force -ErrorAction SilentlyContinue
    }

    It 'creates an empty AssessmentResult with empty collections' {
        $Result = New-TechHubADAssessmentResult

        $Result.Findings.Count | Should -Be 0
        $Result.Observations.Count | Should -Be 0
        $Result.Inventory.Count | Should -Be 0
        $Result.Health.Count | Should -Be 0
        $Result.ProviderResults.Count | Should -Be 0
        $Result.Summary.FindingsCount | Should -Be 0
    }

    It 'adds a finding and updates the severity summary' {
        $Result = New-TechHubADAssessmentResult
        $Finding = [PSCustomObject]@{ Severity = 'High'; CheckId = 'AD-TEST' }

        $Result.AddFinding($Finding)

        $Result.Findings.Count | Should -Be 1
        $Result.Findings[0].CheckId | Should -Be 'AD-TEST'
        $Result.Summary.FindingsCount | Should -Be 1
        $Result.Summary.SeverityCounts['High'] | Should -Be 1
    }

    It 'adds an observation' {
        $Result = New-TechHubADAssessmentResult
        $Observation = [PSCustomObject]@{ Name = 'Observation-1' }

        $Result.AddObservation($Observation)

        $Result.Observations.Count | Should -Be 1
        $Result.Summary.ObservationsCount | Should -Be 1
    }

    It 'adds inventory' {
        $Result = New-TechHubADAssessmentResult
        $Inventory = [PSCustomObject]@{ Name = 'DC01' }

        $Result.AddInventory($Inventory)

        $Result.Inventory.Count | Should -Be 1
        $Result.Summary.InventoryCount | Should -Be 1
    }

    It 'adds a health result' {
        $Result = New-TechHubADAssessmentResult
        $Health = [PSCustomObject]@{ Status = 'Healthy' }

        $Result.AddHealth($Health)

        $Result.Health.Count | Should -Be 1
        $Result.Summary.HealthCount | Should -Be 1
    }

    It 'adds a provider result and supports provider status values' {
        $Result = New-TechHubADAssessmentResult -ProviderStatus 'Available'
        $Result.AddProviderResult([PSCustomObject]@{ Provider = 'Synthetic' })
        $Result.SetProviderStatus('Partial')

        $Result.ProviderResults.Count | Should -Be 1
        $Result.Summary.ProviderResultsCount | Should -Be 1
        $Result.ProviderStatus | Should -Be 'Partial'
    }

    It 'supports data availability values' {
        $Result = New-TechHubADAssessmentResult -DataAvailability 'Complete'

        $Result.SetDataAvailability('NotAvailable')

        $Result.DataAvailability | Should -Be 'NotAvailable'
    }

    It 'supports the defined result types' {
        foreach ($ResultType in @('Finding', 'Observation', 'Inventory', 'Health')) {
            $Result = New-TechHubADAssessmentResult -ResultType $ResultType
            $Result.ResultType | Should -Be $ResultType
        }
    }

    It 'maintains a severity summary for multiple findings' {
        $Result = New-TechHubADAssessmentResult
        $Result.AddFinding([PSCustomObject]@{ Severity = 'High' })
        $Result.AddFinding([PSCustomObject]@{ Severity = 'High' })
        $Result.AddFinding([PSCustomObject]@{ Severity = 'Low' })

        $Result.Summary.FindingsCount | Should -Be 3
        $Result.Summary.SeverityCounts['High'] | Should -Be 2
        $Result.Summary.SeverityCounts['Low'] | Should -Be 1
    }

    It 'calculates duration from required timestamps' {
        $StartedAt = (Get-Date).ToUniversalTime().AddMinutes(-2)
        $CompletedAt = $StartedAt.AddMinutes(2)
        $Result = New-TechHubADAssessmentResult -StartedAt $StartedAt

        $Result.Complete($CompletedAt)

        $Result.StartedAt | Should -Be $StartedAt
        $Result.CompletedAt | Should -Be $CompletedAt
        $Result.Duration.TotalMinutes | Should -Be 2
    }

    It 'provides required metadata fields' {
        $AssessmentId = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $Result = New-TechHubADAssessmentResult `
            -AssessmentId $AssessmentId `
            -Domain 'example.test' `
            -Forest 'example.test' `
            -DomainController 'dc01.example.test' `
            -ProviderStatus 'Available' `
            -DataAvailability 'Complete'

        $Result.AssessmentId | Should -Be $AssessmentId
        $Result.StartedAt | Should -Not -BeNullOrEmpty
        $Result.Domain | Should -Be 'example.test'
        $Result.Forest | Should -Be 'example.test'
        $Result.DomainController | Should -Be 'dc01.example.test'
        $Result.ProviderStatus | Should -Be 'Available'
        $Result.DataAvailability | Should -Be 'Complete'
        $Result.Metadata | Should -Not -BeNullOrEmpty
        $Result.Summary | Should -Not -BeNullOrEmpty
    }

    It 'serializes safely without credentials or executable content' {
        $Result = New-TechHubADAssessmentResult
        $Result.AddFinding([PSCustomObject]@{ Severity = 'Low'; Title = 'Synthetic finding' })
        $Result.AddObservation([PSCustomObject]@{ Name = 'Synthetic observation' })
        $Result.AddInventory([PSCustomObject]@{ Name = 'Synthetic inventory' })
        $Result.AddHealth([PSCustomObject]@{ Status = 'Healthy' })
        $Result.AddProviderResult([PSCustomObject]@{ Name = 'Synthetic provider'; Status = 'Available' })

        $Json = $Result | ConvertTo-Json -Depth 10

        $Json | Should -Match 'Synthetic finding'
        $Json | Should -Not -Match '(?i)password\s*[:=]|secret\s*[:=]|token\s*[:=]|credential\s*[:=]'
        $DynamicMarkers = @('Invoke-' + 'Expression', 'System.Management.Automation.' + 'ScriptBlock', '-----' + 'BEGIN')
        foreach ($Marker in $DynamicMarkers) {
            $Json | Should -Not -Match [regex]::Escape($Marker)
        }
    }

    It 'rejects unsupported provider status and data availability values' {
        { New-TechHubADAssessmentResult -ProviderStatus 'Unknown' } | Should -Throw
        { New-TechHubADAssessmentResult -DataAvailability 'Unknown' } | Should -Throw
    }
}
