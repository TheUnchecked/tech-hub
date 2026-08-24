#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-TechHubADRemoteLocalGroupMembers {
    <#
    .SYNOPSIS
        Collects members of local groups from remote Windows computers.

    .DESCRIPTION
        Read-only assessment using CIM.
        WSMan is attempted first, with DCOM fallback.

    .OUTPUTS
        ComputerName
        GroupName
        GroupMembers
        Status
        IsReadOnly
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('DNSHostName','CN','Host','Computer')]
        [string]$ComputerName
    )

    process {
        $session = $null

        try {
            try {
                $session = New-CimSession `
                    -ComputerName $ComputerName `
                    -ErrorAction Stop
            }
            catch {
                $option = New-CimSessionOption -Protocol Dcom

                $session = New-CimSession `
                    -ComputerName $ComputerName `
                    -SessionOption $option `
                    -ErrorAction Stop
            }

            $groups = Get-CimInstance `
                -CimSession $session `
                -ClassName Win32_Group `
                -Filter 'LocalAccount = TRUE' `
                -ErrorAction Stop

            foreach ($group in @($groups)) {

                try {
                    $members = Get-CimAssociatedInstance `
                        -CimSession $session `
                        -InputObject $group `
                        -Association Win32_GroupUser `
                        -ResultClassName Win32_Account `
                        -ErrorAction Stop

                    $values = @(
                        $members |
                        Sort-Object Domain, Name |
                        ForEach-Object {
                            '{0}\{1}' -f $_.Domain, $_.Name
                        }
                    )

                    [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        GroupName    = $group.Name
                        GroupMembers = ($values -join ', ')
                        Status       = 'Available'
                        IsReadOnly   = $true
                    }
                }
                catch {

                    [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        GroupName    = $group.Name
                        GroupMembers = ''
                        Status       = 'Partial'
                        IsReadOnly   = $true
                    }
                }
            }
        }
        catch {
            Write-Error `
                -Message "[$ComputerName] Remote query failed: $($_.Exception.Message)"
        }
        finally {
            if ($session) {
                Remove-CimSession `
                    -CimSession $session `
                    -ErrorAction SilentlyContinue
            }
        }
    }
}