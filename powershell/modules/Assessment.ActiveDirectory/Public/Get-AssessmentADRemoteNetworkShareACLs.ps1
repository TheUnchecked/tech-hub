#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteNetworkShareACLs {
    <#
    .SYNOPSIS
        Retrieves SMB shares and share-level ACLs from remote Windows computers.

    .DESCRIPTION
        Read-only assessment collector.
        Uses Get-SmbShare/Get-SmbShareAccess when available and
        falls back to Win32_* CIM classes.

    .PARAMETER ComputerName
        Target computer.

    .PARAMETER IncludeAdminShares
        Include default administrative shares.

    .PARAMETER Credential
        Optional alternate credential.

    .OUTPUTS
        ComputerName
        ShareName
        SharePath
        ACL
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
        [Alias('CN','Computer','Host','DNSHostName')]
        [string]$ComputerName,

        [switch]$IncludeAdminShares,

        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        $defaultAdminShares = @(
            'ADMIN$',
            'IPC$',
            'C$',
            'D$',
            'E$',
            'F$',
            'G$',
            'H$'
        )

        function Resolve-AssessmentSid {
            param(
                [Parameter(Mandatory)]
                [string]$SidString
            )

            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)

                return $sid.Translate(
                    [System.Security.Principal.NTAccount]
                ).Value
            }
            catch {
                return $SidString
            }
        }

        function Convert-AssessmentShareAccessMask {
            param(
                [Parameter(Mandatory)]
                [int]$Mask
            )

            if (($Mask -band 0x1F01FF) -eq 0x1F01FF) {
                return 'Full'
            }

            if (($Mask -band 0x1301BF) -eq 0x1301BF) {
                return 'Change'
            }

            if (($Mask -band 0x120089) -eq 0x120089) {
                return 'Read'
            }

            return ('Custom(0x{0:X})' -f $Mask)
        }
    }

    process {

        $cimSession = $null

        try {

            $cimParams = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
            }

            if ($PSBoundParameters.ContainsKey('Credential')) {
                $cimParams.Credential = $Credential
            }

            try {
                $cimSession = New-CimSession @cimParams
            }
            catch {
                $option = New-CimSessionOption -Protocol Dcom

                $cimParams.SessionOption = $option

                $cimSession = New-CimSession @cimParams
            }

            $useSmb = $true

            try {

                $shares = Get-SmbShare `
                    -CimSession $cimSession `
                    -ErrorAction Stop

                if (-not $IncludeAdminShares) {
                    $shares = @(
                        $shares |
                        Where-Object {
                            $defaultAdminShares -notcontains $_.Name
                        }
                    )
                }
            }
            catch {

                $useSmb = $false

                $shares = Get-CimInstance `
                    -ClassName Win32_Share `
                    -CimSession $cimSession `
                    -ErrorAction Stop

                if (-not $IncludeAdminShares) {
                    $shares = @(
                        $shares |
                        Where-Object {
                            $defaultAdminShares -notcontains $_.Name
                        }
                    )
                }
            }

            foreach ($share in @($shares)) {

                $aclEntries = @()

                if ($useSmb) {

                    $aclEntries = @(
                        Get-SmbShareAccess `
                            -Name $share.Name `
                            -CimSession $cimSession `
                            -ErrorAction SilentlyContinue |
                        ForEach-Object {

                            [PSCustomObject][ordered]@{
                                Subject           = $_.AccountName
                                AccessControlType = $_.AccessControlType
                                AccessRight       = $_.AccessRight
                            }
                        }
                    )

                    [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        ShareName    = $share.Name
                        SharePath    = $share.Path
                        ACL          = $aclEntries
                        IsReadOnly   = $true
                    }
                }
                else {

                    $nameFilter = "Name='{0}'" -f (
                        $share.Name -replace "'", "''"
                    )

                    $securitySetting = Get-CimInstance `
                        -ClassName Win32_LogicalShareSecuritySetting `
                        -Filter $nameFilter `
                        -CimSession $cimSession `
                        -ErrorAction SilentlyContinue

                    if ($securitySetting) {

                        $sdResult = Invoke-CimMethod `
                            -InputObject $securitySetting `
                            -MethodName GetSecurityDescriptor `
                            -ErrorAction SilentlyContinue

                        if (
                            $sdResult.ReturnValue -eq 0 -and
                            $sdResult.Descriptor -and
                            $sdResult.Descriptor.DACL
                        ) {

                            foreach ($ace in $sdResult.Descriptor.DACL) {

                                $subject = $null

                                if ($ace.Trustee.SIDString) {
                                    $subject = Resolve-AssessmentSid `
                                        -SidString $ace.Trustee.SIDString
                                }
                                elseif (
                                    $ace.Trustee.Domain -and
                                    $ace.Trustee.Name
                                ) {
                                    $subject = '{0}\{1}' -f `
                                        $ace.Trustee.Domain,
                                        $ace.Trustee.Name
                                }
                                else {
                                    $subject = $ace.Trustee.Name
                                }

                                $accessType = switch ($ace.AceType) {
                                    0 { 'Allow' }
                                    1 { 'Deny' }
                                    default {
                                        "Unknown({0})" -f $ace.AceType
                                    }
                                }

                                $right = Convert-AssessmentShareAccessMask `
                                    -Mask ([int]$ace.AccessMask)

                                $aclEntries += `
                                    [PSCustomObject][ordered]@{
                                        Subject           = $subject
                                        AccessControlType = $accessType
                                        AccessRight       = $right
                                    }
                            }
                        }
                    }

                    [PSCustomObject][ordered]@{
                        ComputerName = $ComputerName
                        ShareName    = $share.Name
                        SharePath    = $share.Path
                        ACL          = $aclEntries
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

            if ($cimSession) {
                Remove-CimSession `
                    -CimSession $cimSession `
                    -ErrorAction SilentlyContinue
            }
        }
    }
}