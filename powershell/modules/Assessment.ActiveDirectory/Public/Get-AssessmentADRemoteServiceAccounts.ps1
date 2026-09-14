#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteServiceAccounts {
    <#
    .SYNOPSIS
        Returns the logon account for each Windows service on a remote computer.

    .DESCRIPTION
        Read-only query for Win32_Service via CIM (WSMan, falling back to
        DCOM). Normalizes the logon account to backslash notation:
          - LocalSystem -> NT AUTHORITY\SYSTEM
          - .\User      -> ComputerName\User
          - other forms are passed through as-is (DOMAIN\User,
            NT AUTHORITY\LocalService, NT SERVICE\*, ...)

    .PARAMETER ComputerName
        One or more remote computers. Supports pipeline input.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName, ServiceName, AccountName, Transport, IsReadOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('Computer', 'CN', 'Hostname', 'Name')]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {

        $TransportParameters = @{
            ComputerName = $ComputerName
            ScriptBlock  = {
                param($Session)

                Get-CimInstance -CimSession $Session -ClassName Win32_Service -ErrorAction Stop |
                    Select-Object Name, StartName
            }
        }

        if ($null -ne $Credential) {
            $TransportParameters.Credential = $Credential
        }

        try {
            $TransportResult = Invoke-AssessmentADRemoteCimQuery @TransportParameters
        }
        catch {
            Write-Error -Message "[$ComputerName] Remote query failed: $($_.Exception.Message)"
            return
        }

        if ($TransportResult.Status -ne 'Available') {
            Write-Error -Message "[$ComputerName] Remote query failed: $($TransportResult.ErrorMessage)"
            return
        }

        foreach ($Service in @($TransportResult.Data)) {

            if ($null -eq $Service) { continue }

            $StartName = [string]$Service.StartName

            $AccountName = switch -Regex ($StartName) {
                '^(?i)LocalSystem$' { 'NT AUTHORITY\SYSTEM' }
                '^[.]\\'            { $StartName -replace '^[.]\\', "$ComputerName\" }
                default             { $StartName }
            }

            [PSCustomObject][ordered]@{
                ComputerName = $ComputerName
                ServiceName  = $Service.Name
                AccountName  = $AccountName
                Transport    = $TransportResult.Transport
                IsReadOnly   = $true
            }
        }
    }
}
