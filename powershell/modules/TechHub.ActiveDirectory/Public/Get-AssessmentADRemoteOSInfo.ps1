#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteOSInfo {
    <#
    .SYNOPSIS
        Collects operating system information from a remote Windows computer.

    .DESCRIPTION
        Performs a read-only remote OS assessment.

        Transport preference:

        1. CIM / WSMan
        2. CIM / DCOM

        The collector returns the actual remote operating system
        information and ProductType classification data.

        ProductType:

        1 = Client
        2 = Domain Controller
        3 = Server

    .PARAMETER ComputerName
        Remote computer name.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName
        OSCaption
        OSVersion
        OSBuildNumber
        OSSKU
        ProductType
        TargetType
        WindowsInstallationType
        Status
        DataAvailability
        CollectionMethod
        ErrorType
        ErrorMessage
        IsReadOnly
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'Computer',
            'CN',
            'Name',
            'DNSHostName'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        Write-Verbose `
            "Collecting OS information from [$ComputerName]."

        try {

            # ====================================================
            # CIM REMOTE QUERY
            # ====================================================

            $InvokeParams = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
                ScriptBlock  = {
                    param(
                        $Session
                    )

                    Get-CimInstance `
                        -CimSession $Session `
                        -ClassName Win32_OperatingSystem `
                        -ErrorAction Stop |
                    Select-Object `
                        CSName,
                        Caption,
                        Version,
                        BuildNumber,
                        OperatingSystemSKU,
                        ProductType
                }
            }

            if (
                $PSBoundParameters.ContainsKey(
                    'Credential'
                )
            ) {

                $InvokeParams.Credential = $Credential
            }

            # ====================================================
            # USE INTERNAL CIM TRANSPORT HELPER
            # ====================================================

            $TransportResult = & (
                Get-Module TechHub.ActiveDirectory
            ) {

                Invoke-AssessmentADRemoteCimQuery `
                    -ComputerName $ComputerName `
                    -Credential $Credential `
                    -ScriptBlock {
                        param(
                            $Session
                        )

                        Get-CimInstance `
                            -CimSession $Session `
                            -ClassName Win32_OperatingSystem `
                            -ErrorAction Stop |
                        Select-Object `
                            CSName,
                            Caption,
                            Version,
                            BuildNumber,
                            OperatingSystemSKU,
                            ProductType
                    }
            }

            # ====================================================
            # TRANSPORT FAILURE
            # ====================================================

            if (
                $TransportResult.Status -ne 'Available'
            ) {

                [PSCustomObject][ordered]@{

                    ComputerName = `
                        $ComputerName

                    OSCaption = $null

                    OSVersion = $null

                    OSBuildNumber = $null

                    OSSKU = $null

                    ProductType = $null

                    TargetType = 'Unknown'

                    WindowsInstallationType = $null

                    Status = 'NotAvailable'

                    DataAvailability = 'NotAvailable'

                    CollectionMethod = 'None'

                    ErrorType = `
                        $TransportResult.ErrorType

                    ErrorMessage = `
                        $TransportResult.ErrorMessage

                    IsReadOnly = $true
                }

                return
            }

            # ====================================================
            # REMOTE DATA
            # ====================================================

            $OS = @(
                $TransportResult.Data
            ) | Select-Object -First 1

            if ($null -eq $OS) {

                [PSCustomObject][ordered]@{

                    ComputerName = `
                        $ComputerName

                    OSCaption = $null

                    OSVersion = $null

                    OSBuildNumber = $null

                    OSSKU = $null

                    ProductType = $null

                    TargetType = 'Unknown'

                    WindowsInstallationType = $null

                    Status = 'NotAvailable'

                    DataAvailability = 'NotAvailable'

                    CollectionMethod = `
                        $TransportResult.Transport

                    ErrorType = 'NoData'

                    ErrorMessage = `
                        'Remote operating system query returned no data.'

                    IsReadOnly = $true
                }

                return
            }

            # ====================================================
            # PRODUCT TYPE
            # ====================================================

            $ProductType = $null

            if (
                $OS.PSObject.Properties['ProductType']
            ) {

                try {

                    $ProductType = `
                        [int]$OS.ProductType
                }
                catch {

                    $ProductType = $null
                }
            }

            # ====================================================
            # TARGET TYPE
            # ====================================================

            $TargetType = 'Unknown'

            switch ($ProductType) {

                1 {
                    $TargetType = 'Client'
                }

                2 {
                    $TargetType = 'DomainController'
                }

                3 {
                    $TargetType = 'Server'
                }
            }

            # ====================================================
            # COLLECTION METHOD
            # ====================================================

            $CollectionMethod = 'WMI'

            if (
                $TransportResult.Transport -eq 'WSMan'
            ) {

                $CollectionMethod = 'WinRM'
            }

            # ====================================================
            # RESULT
            # ====================================================

            [PSCustomObject][ordered]@{

                ComputerName = `
                    $ComputerName

                OSCaption = `
                    [string]$OS.Caption

                OSVersion = `
                    [string]$OS.Version

                OSBuildNumber = `
                    [string]$OS.BuildNumber

                OSSKU = `
                    $OS.OperatingSystemSKU

                ProductType = `
                    $ProductType

                TargetType = `
                    $TargetType

                WindowsInstallationType = `
                    $null

                Status = `
                    'Available'

                DataAvailability = `
                    'Available'

                CollectionMethod = `
                    $CollectionMethod

                ErrorType = `
                    $null

                ErrorMessage = `
                    $null

                IsReadOnly = `
                    $true
            }
        }
        catch {

            [PSCustomObject][ordered]@{

                ComputerName = `
                    $ComputerName

                OSCaption = $null

                OSVersion = $null

                OSBuildNumber = $null

                OSSKU = $null

                ProductType = $null

                TargetType = 'Unknown'

                WindowsInstallationType = $null

                Status = 'NotAvailable'

                DataAvailability = 'NotAvailable'

                CollectionMethod = 'None'

                ErrorType = 'RemoteOSQueryError'

                ErrorMessage = `
                    $_.Exception.Message

                IsReadOnly = $true
            }
        }
    }
}