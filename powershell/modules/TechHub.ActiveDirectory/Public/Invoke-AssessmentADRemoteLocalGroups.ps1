#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-AssessmentADAssessment {

    [CmdletBinding()]

    param (

        [Parameter()]
        [object]$Registry,

        [Parameter()]
        [string[]]$CheckId,

        [Parameter()]
        [string[]]$Category,

        [Parameter()]
        [object]$Provider,

        [Parameter()]
        [string]$Server,

        [Parameter()]
        [string]$SearchBase
    )

    # ============================================================
    # REGISTRY
    # ============================================================

    if ($null -eq $Registry) {

        $Registry = New-AssessmentADCheckRegistry
    }

    # ============================================================
    # ASSESSMENT
    # ============================================================

    $Assessment = New-AssessmentADAssessmentResult

    $Assessment.Metadata = [PSCustomObject][ordered]@{

        Engine        = 'TechHub.ActiveDirectory'

        EngineVersion = '1.0.0'

        CheckResults  =
            New-Object System.Collections.ArrayList
    }

    # ============================================================
    # SUMMARY
    # ============================================================

    $Assessment.Summary |
        Add-Member `
            -MemberType NoteProperty `
            -Name ChecksDiscovered `
            -Value 0

    $Assessment.Summary |
        Add-Member `
            -MemberType NoteProperty `
            -Name ChecksExecuted `
            -Value 0

    $Assessment.Summary |
        Add-Member `
            -MemberType NoteProperty `
            -Name ChecksSkipped `
            -Value 0

    $Assessment.Summary |
        Add-Member `
            -MemberType NoteProperty `
            -Name ChecksFailed `
            -Value 0

    # ============================================================
    # LOAD DEFINITIONS
    # ============================================================

    $Definitions = @(
        $Registry.GetAll()
    )

    # ============================================================
    # FILTER CHECK ID
    # ============================================================

    if (
        $PSBoundParameters.ContainsKey('CheckId')
    ) {

        $Definitions = @(
            $Definitions |
                Where-Object {
                    $CheckId -contains $_.CheckId
                }
        )
    }

    # ============================================================
    # FILTER CATEGORY
    # ============================================================

    if (
        $PSBoundParameters.ContainsKey('Category')
    ) {

        $Definitions = @(
            $Definitions |
                Where-Object {
                    $Category -contains $_.Category
                }
        )
    }

    # ============================================================
    # DISCOVERED
    # ============================================================

    $Assessment.Summary.ChecksDiscovered =
        $Definitions.Count

    # ============================================================
    # PROVIDER
    # ============================================================

    $ProviderCreationError = $null

    $ProviderRequired =
        @(
            $Definitions |
                Where-Object {

                    $RequiredProviders =
                        @($_.RequiredProviders)

                    $RequiredProviders -contains 'TechHubAD' -or
                    $RequiredProviders -contains 'TechHubADProvider'
                }
        ).Count -gt 0

    if (
        $null -eq $Provider -and
        $ProviderRequired
    ) {

        try {

            Write-Verbose `
                -Message `
                'Creating one TechHubADProvider for this assessment.'

            $Provider =
                New-AssessmentADProvider `
                    -Server $Server `
                    -ErrorAction Stop
        }
        catch {

            $ProviderCreationError = $_

            Write-Verbose `
                -Message `
                (
                    'Unable to create TechHubADProvider: {0}' -f
                    $_.Exception.Message
                )
        }
    }

    # ============================================================
    # EXECUTE CHECKS
    # ============================================================

    foreach ($Definition in $Definitions) {

        $CheckStartedAt =
            (Get-Date).ToUniversalTime()

        $CheckCompletedAt = $null

        $RequiredProviders =
            @($Definition.RequiredProviders)

        $DefinitionRequiresProvider =
            $RequiredProviders -contains 'TechHubAD' -or
            $RequiredProviders -contains 'TechHubADProvider'

        # ========================================================
        # CHECK DISABLED
        # ========================================================

        if (
            -not $Definition.Enabled
        ) {

            $CheckCompletedAt =
                (Get-Date).ToUniversalTime()

            $CheckResult =
                New-AssessmentADCheckExecutionError `
                    -Definition $Definition `
                    -Status 'NotAvailable' `
                    -ErrorType 'CheckDisabled' `
                    -ErrorMessage `
                        'The check is disabled in the registry.' `
                    -StartedAt $CheckStartedAt `
                    -CompletedAt $CheckCompletedAt

            [void]$Assessment.Metadata.CheckResults.Add(
                $CheckResult
            )

            $Assessment.Summary.ChecksSkipped++

            continue
        }

        # ========================================================
        # READ ONLY VALIDATION
        # ========================================================

        if (
            $Definition.IsReadOnly -ne $true
        ) {

            $CheckCompletedAt =
                (Get-Date).ToUniversalTime()

            $CheckResult =
                New-AssessmentADCheckExecutionError `
                    -Definition $Definition `
                    -Status 'Error' `
                    -ErrorType 'ReadOnlyViolation' `
                    -ErrorMessage `
                        'The registered check does not declare IsReadOnly = $true.' `
                    -StartedAt $CheckStartedAt `
                    -CompletedAt $CheckCompletedAt

            [void]$Assessment.Metadata.CheckResults.Add(
                $CheckResult
            )

            $Assessment.Summary.ChecksFailed++

            continue
        }

        # ========================================================
        # RESOLVE FUNCTION
        # ========================================================

        $Command = $null

        try {

            $Command =
                Get-Command `
                    -Name ([string]$Definition.FunctionName) `
                    -CommandType Function `
                    -ErrorAction Stop
        }
        catch {

            $CheckCompletedAt =
                (Get-Date).ToUniversalTime()

            $CheckResult =
                New-AssessmentADCheckExecutionError `
                    -Definition $Definition `
                    -Status 'Error' `
                    -ErrorType 'FunctionNotFound' `
                    -ErrorMessage $_.Exception.Message `
                    -StartedAt $CheckStartedAt `
                    -CompletedAt $CheckCompletedAt

            [void]$Assessment.Metadata.CheckResults.Add(
                $CheckResult
            )

            $Assessment.Summary.ChecksFailed++

            continue
        }

        # ========================================================
        # PROVIDER CREATION ERROR
        # ========================================================

        if (
            $DefinitionRequiresProvider -and
            $null -eq $Provider -and
            $null -ne $ProviderCreationError -and
            $Command.Parameters.ContainsKey('Provider')
        ) {

            $CheckCompletedAt =
                (Get-Date).ToUniversalTime()

            $CheckResult =
                New-AssessmentADCheckExecutionError `
                    -Definition $Definition `
                    -Status 'Error' `
                    -ErrorType 'ProviderCreationError' `
                    -ErrorMessage `
                        $ProviderCreationError.Exception.Message `
                    -StartedAt $CheckStartedAt `
                    -CompletedAt $CheckCompletedAt

            [void]$Assessment.Metadata.CheckResults.Add(
                $CheckResult
            )

            $Assessment.Summary.ChecksFailed++

            continue
        }

        # ========================================================
        # BUILD CHECK PARAMETERS
        # ========================================================

        try {

            $Parameters = @{}

            # ----------------------------------------------------
            # PROVIDER
            # ----------------------------------------------------

            if (
                $null -ne $Provider -and
                $Command.Parameters.ContainsKey('Provider')
            ) {

                $Parameters.Provider = $Provider
            }

            # ----------------------------------------------------
            # SERVER
            # ----------------------------------------------------

            if (
                -not [string]::IsNullOrWhiteSpace($Server) -and
                $Command.Parameters.ContainsKey('Server')
            ) {

                $Parameters.Server = $Server
            }

            # ----------------------------------------------------
            # COMPUTER NAME
            #
            # IMPORTANT:
            #
            # Remote checks such as:
            #
            # Get-AssessmentADRemoteLocalGroups
            #
            # use ComputerName rather than Server.
            #
            # The assessment engine exposes Server as the generic
            # target parameter, therefore map Server -> ComputerName
            # when the registered check supports ComputerName.
            # ----------------------------------------------------

            if (
                -not [string]::IsNullOrWhiteSpace($Server) -and
                $Command.Parameters.ContainsKey('ComputerName')
            ) {

                $Parameters.ComputerName = $Server
            }

            # ----------------------------------------------------
            # SEARCH BASE
            # ----------------------------------------------------

            if (
                -not [string]::IsNullOrWhiteSpace($SearchBase) -and
                $Command.Parameters.ContainsKey('SearchBase')
            ) {

                $Parameters.SearchBase = $SearchBase
            }

            # ====================================================
            # EXECUTE CHECK
            # ====================================================

            Write-Verbose `
                -Message `
                (
                    'Executing registered check {0}.' -f
                    $Definition.CheckId
                )

            $Outputs = @(
                & $Command @Parameters
            )

            # ====================================================
            # PROCESS OUTPUT
            # ====================================================

            foreach ($Output in $Outputs) {

                if (
                    $null -ne $Output -and
                    $null -ne $Output.PSObject.Properties['FindingId']
                ) {

                    $Assessment.AddFinding(
                        $Output
                    )
                }
                else {

                    Write-Verbose `
                        -Message `
                        (
                            'Check {0} returned a non-finding object.' -f
                            $Definition.CheckId
                        )
                }
            }

            $Assessment.Summary.ChecksExecuted++
        }
        catch {

            # ====================================================
            # CHECK EXECUTION ERROR
            # ====================================================

            $CheckCompletedAt =
                (Get-Date).ToUniversalTime()

            $ErrorType =
                'CheckExecutionError'

            if (
                $_.Exception.Message -match
                '(?i)access denied|unauthorized'
            ) {

                $ErrorType =
                    'AccessDenied'
            }
            elseif (
                $_.Exception.Message -match
                '(?i)LDAP|directory service'
            ) {

                $ErrorType =
                    'LdapError'
            }
            elseif (
                $_.Exception.Message -match
                '(?i)server|unreachable|timeout'
            ) {

                $ErrorType =
                    'ServerUnavailable'
            }

            $CheckResult =
                New-AssessmentADCheckExecutionError `
                    -Definition $Definition `
                    -Status 'Error' `
                    -ErrorType $ErrorType `
                    -ErrorMessage $_.Exception.Message `
                    -StartedAt $CheckStartedAt `
                    -CompletedAt $CheckCompletedAt

            [void]$Assessment.Metadata.CheckResults.Add(
                $CheckResult
            )

            $Assessment.Summary.ChecksFailed++

            Write-Verbose `
                -Message `
                (
                    'Check {0} failed: {1}' -f
                    $Definition.CheckId,
                    $_.Exception.Message
                )
        }
    }

    # ============================================================
    # PROVIDER RESULTS
    # ============================================================

    if (
        $null -ne $Provider -and
        $null -ne $Provider.PSObject.Properties['Results']
    ) {

        foreach (
            $ProviderResult in @($Provider.Results)
        ) {

            if (
                $null -ne $ProviderResult
            ) {

                $Assessment.AddProviderResult(
                    $ProviderResult
                )
            }
        }
    }

    # ============================================================
    # PROVIDER STATUS
    # ============================================================

    $AssessmentProviderStatus =
        'NotAvailable'

    if (
        $null -ne $ProviderCreationError
    ) {

        $AssessmentProviderStatus =
            'Error'
    }
    elseif (
        $null -ne $Provider
    ) {

        $AssessmentProviderStatus =
            'Available'

        if (
            $null -ne
            $Provider.PSObject.Methods['GetProviderStatus']
        ) {

            try {

                $ProviderStatusResult =
                    $Provider.GetProviderStatus()

                if (
                    $null -ne $ProviderStatusResult -and
                    $null -ne $ProviderStatusResult.Status
                ) {

                    $AssessmentProviderStatus =
                        [string]$ProviderStatusResult.Status
                }
            }
            catch {

                Write-Verbose `
                    -Message `
                    (
                        'Unable to collect final provider status: {0}' -f
                        $_.Exception.Message
                    )
            }
        }
    }

    # ============================================================
    # FINAL ASSESSMENT STATUS
    # ============================================================

    $Assessment.SetProviderStatus(
        $AssessmentProviderStatus
    )

    $DataAvailability =
        if (
            $Assessment.Summary.ChecksFailed -gt 0
        ) {
            'Partial'
        }
        else {
            'Complete'
        }

    $Assessment.SetDataAvailability(
        $DataAvailability
    )

    # ============================================================
    # COMPLETE
    # ============================================================

    $Assessment.Complete(
        (Get-Date).ToUniversalTime()
    )

    # ============================================================
    # RETURN
    # ============================================================

    $Assessment
}