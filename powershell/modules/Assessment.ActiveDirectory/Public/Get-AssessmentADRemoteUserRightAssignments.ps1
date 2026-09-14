#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteUserRightAssignments {
    <#
    .SYNOPSIS
        Returns local user right assignments (URAs) from a remote computer.

    .DESCRIPTION
        Exports the local security policy's User Rights via secedit on
        the target computer, parses the [Privilege Rights] section,
        resolves SIDs to backslash notation, and reports one record per
        assigned right with the GPO display name.

    .PARAMETER ComputerName
        One or more computer names. Supports pipeline input.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName, AssignmentName, Assignees
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('CN', 'Server', 'Name', 'Computer')]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {

        $SeToGpoName = @{
            'SeAssignPrimaryTokenPrivilege'     = 'Replace a process level token'
            'SeAuditPrivilege'                  = 'Generate security audits'
            'SeBackupPrivilege'                 = 'Back up files and directories'
            'SeBatchLogonRight'                 = 'Log on as a batch job'
            'SeChangeNotifyPrivilege'           = 'Bypass traverse checking'
            'SeCreateGlobalPrivilege'           = 'Create global objects'
            'SeCreatePagefilePrivilege'         = 'Create a pagefile'
            'SeCreatePermanentPrivilege'        = 'Create permanent shared objects'
            'SeCreateSymbolicLinkPrivilege'     = 'Create symbolic links'
            'SeCreateTokenPrivilege'            = 'Create a token object'
            'SeDebugPrivilege'                  = 'Debug programs'
            'SeDenyBatchLogonRight'             = 'Deny log on as a batch job'
            'SeDenyInteractiveLogonRight'       = 'Deny log on locally'
            'SeDenyNetworkLogonRight'           = 'Deny access to this computer from the network'
            'SeDenyRemoteInteractiveLogonRight' = 'Deny log on through Remote Desktop Services'
            'SeDenyServiceLogonRight'           = 'Deny log on as a service'
            'SeEnableDelegationPrivilege'       = 'Enable computer and user accounts to be trusted for delegation'
            'SeImpersonatePrivilege'            = 'Impersonate a client after authentication'
            'SeIncreaseBasePriorityPrivilege'   = 'Increase scheduling priority'
            'SeIncreaseQuotaPrivilege'          = 'Adjust memory quotas for a process'
            'SeIncreaseWorkingSetPrivilege'     = 'Increase a process working set'
            'SeInteractiveLogonRight'           = 'Allow log on locally'
            'SeLoadDriverPrivilege'             = 'Load and unload device drivers'
            'SeLockMemoryPrivilege'             = 'Lock pages in memory'
            'SeMachineAccountPrivilege'         = 'Add workstations to domain'
            'SeManageVolumePrivilege'           = 'Manage auditing and security log'
            'SeProfileSingleProcessPrivilege'   = 'Profile single process'
            'SeRelabelPrivilege'                = 'Modify an object label'
            'SeRemoteInteractiveLogonRight'     = 'Allow log on through Remote Desktop Services'
            'SeRemoteShutdownPrivilege'         = 'Force shutdown from a remote system'
            'SeRestorePrivilege'                = 'Restore files and directories'
            'SeSecurityPrivilege'               = 'Manage auditing and security log'
            'SeServiceLogonRight'               = 'Log on as a service'
            'SeShutdownPrivilege'               = 'Shut down the system'
            'SeSyncAgentPrivilege'              = 'Synchronize directory service data'
            'SeSystemEnvironmentPrivilege'      = 'Modify firmware environment values'
            'SeSystemProfilePrivilege'          = 'Profile system performance'
            'SeSystemtimePrivilege'             = 'Change the system time'
            'SeTakeOwnershipPrivilege'          = 'Take ownership of files or other objects'
            'SeTcbPrivilege'                    = 'Act as part of the operating system'
            'SeTimeZonePrivilege'               = 'Change the time zone'
            'SeTrustedCredManAccessPrivilege'   = 'Access Credential Manager as a trusted caller'
            'SeUndockPrivilege'                 = 'Remove computer from docking station'
            'SeNetworkLogonRight'               = 'Access this computer from the network'
        }

        $Collector = {
            param([string]$CompLabel, [hashtable]$Map)

            $ErrorActionPreference = 'Stop'

            $Tmp = Join-Path $env:TEMP ("secpol_{0:yyyyMMddHHmmss}_{1}.inf" -f (Get-Date), [guid]::NewGuid())

            try {
                & secedit.exe /export /cfg $Tmp /areas USER_RIGHTS | Out-Null

                $Lines = Get-Content -Path $Tmp -Encoding Unicode
                $InSection = $false

                foreach ($Line in $Lines) {

                    if ($Line -match '^\s*\[Privilege Rights\]\s*$') {
                        $InSection = $true
                        continue
                    }

                    if ($InSection -and $Line -match '^\s*\[') { break }
                    if (-not $InSection) { continue }

                    if ($Line -notmatch '^\s*Se[^=]+\s*=') { continue }

                    $EqIndex = $Line.IndexOf('=')
                    if ($EqIndex -lt 0) { continue }

                    $PrivilegeId = $Line.Substring(0, $EqIndex).Trim()
                    $Value = $Line.Substring($EqIndex + 1).Trim()

                    $Items = @()
                    if ($Value) {
                        $Items = $Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
                    }

                    $Resolved = New-Object System.Collections.Generic.List[string]

                    foreach ($Item in $Items) {

                        $Token = $Item.Trim('*').Trim()

                        if ($Token -match '^S-1-') {
                            try {
                                $Sid = New-Object System.Security.Principal.SecurityIdentifier($Token)
                                $Resolved.Add($Sid.Translate([System.Security.Principal.NTAccount]).Value)
                            }
                            catch {
                                $Resolved.Add($Token)
                            }
                        }
                        elseif ($Token -match '\\') {
                            $Resolved.Add($Token)
                        }
                        else {
                            try {
                                $Nt = New-Object System.Security.Principal.NTAccount($Token)
                                $Sid = $Nt.Translate([System.Security.Principal.SecurityIdentifier])
                                $Resolved.Add($Sid.Translate([System.Security.Principal.NTAccount]).Value)
                            }
                            catch {
                                $Resolved.Add($Token)
                            }
                        }
                    }

                    $DisplayName = $Map[$PrivilegeId]
                    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                        $DisplayName = $PrivilegeId
                    }

                    [PSCustomObject]@{
                        ComputerName   = $CompLabel
                        AssignmentName = $DisplayName
                        Assignees      = ($Resolved -join ', ')
                    }
                }
            }
            finally {
                if (Test-Path $Tmp) {
                    Remove-Item -Path $Tmp -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    process {

        foreach ($Computer in $ComputerName) {

            if ([string]::IsNullOrWhiteSpace($Computer)) { continue }

            $IsLocal = $Computer -eq '.' -or $Computer -eq 'localhost' -or
                $Computer.Trim().ToUpperInvariant() -eq $env:COMPUTERNAME.ToUpperInvariant()

            $NormalizedLabel = if ($IsLocal) { $env:COMPUTERNAME } else { $Computer }

            try {
                $Results = if ($IsLocal) {
                    & $Collector -CompLabel $NormalizedLabel -Map $SeToGpoName
                }
                else {
                    $InvokeParameters = @{
                        ComputerName    = $Computer
                        ScriptBlock     = $Collector
                        ArgumentList    = @($NormalizedLabel, $SeToGpoName)
                        ErrorAction     = 'Stop'
                        HideComputerName = $true
                    }

                    if ($null -ne $Credential) {
                        $InvokeParameters.Credential = $Credential
                    }

                    Invoke-Command @InvokeParameters
                }

                $Results | Select-Object -Property ComputerName, AssignmentName, Assignees
            }
            catch {
                Write-Error -Message "[$Computer] Remote query failed: $($_.Exception.Message)"
            }
        }
    }
}
