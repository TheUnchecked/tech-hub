function Resolve-TechHubADGroupMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GroupIdentity,

        [Parameter()]
        [string[]]$MembershipPath = @(),

        [Parameter()]
        [hashtable]$VisitedGroups = @{}
    )

    if ($VisitedGroups.ContainsKey($GroupIdentity)) {
        Write-Verbose -Message ('Skipping already visited group {0}.' -f $GroupIdentity)
        return
    }
    $VisitedGroups[$GroupIdentity] = $true

    $Members = @()
    try {
        $Members = @(Get-ADGroupMember -Identity $GroupIdentity -ErrorAction Stop)
    }
    catch {
        Write-Verbose -Message ('Unable to read members of group {0}: {1}' -f $GroupIdentity, $_.Exception.Message)
        return
    }

    foreach ($Member in $Members) {
        $Name = $null
        $SamAccountName = $null
        $ObjectClass = 'Unknown'
        $ObjectGuid = $null
        $DistinguishedName = $null
        $Enabled = $null
        $AdminCount = $null
        $PasswordNeverExpires = $null
        $MemberSid = $null
        $Detail = $null

        foreach ($PropertyName in @('Name', 'SamAccountName', 'DistinguishedName', 'ObjectClass', 'ObjectGUID', 'SID')) {
            if ($null -ne $Member.PSObject.Properties[$PropertyName]) {
                $Value = $Member.PSObject.Properties[$PropertyName].Value
                switch ($PropertyName) {
                    'Name' { $Name = [string]$Value }
                    'SamAccountName' { $SamAccountName = [string]$Value }
                    'DistinguishedName' { $DistinguishedName = [string]$Value }
                    'ObjectClass' {
                        $MemberClasses = @($Value)
                        if ($MemberClasses -contains 'user') { $ObjectClass = 'User' }
                        elseif ($MemberClasses -contains 'computer') { $ObjectClass = 'Computer' }
                        elseif ($MemberClasses -contains 'group') { $ObjectClass = 'Group' }
                    }
                    'ObjectGUID' { try { $ObjectGuid = [guid]$Value } catch { Write-Verbose -Message 'A member has an invalid ObjectGUID.' } }
                    'SID' { $MemberSid = [string]$Value }
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($DistinguishedName)) {
            try {
                $Detail = Get-ADObject -Identity $DistinguishedName -Properties @('Name', 'SamAccountName', 'ObjectClass', 'ObjectGUID', 'DistinguishedName', 'Enabled', 'adminCount', 'PasswordNeverExpires', 'UserAccountControl', 'SID') -ErrorAction Stop
            }
            catch {
                Write-Verbose -Message ('Unable to resolve member {0}: {1}' -f $DistinguishedName, $_.Exception.Message)
            }
        }

        if ($null -ne $Detail) {
            if ($null -ne $Detail.PSObject.Properties['Name']) { $Name = [string]$Detail.PSObject.Properties['Name'].Value }
            if ($null -ne $Detail.PSObject.Properties['SamAccountName']) { $SamAccountName = [string]$Detail.PSObject.Properties['SamAccountName'].Value }
            if ($null -ne $Detail.PSObject.Properties['DistinguishedName']) { $DistinguishedName = [string]$Detail.PSObject.Properties['DistinguishedName'].Value }
            if ($null -ne $Detail.PSObject.Properties['ObjectGUID']) { try { $ObjectGuid = [guid]$Detail.PSObject.Properties['ObjectGUID'].Value } catch { Write-Verbose -Message 'A resolved member has an invalid ObjectGUID.' } }
            $DetailClasses = @()
            if ($null -ne $Detail.PSObject.Properties['ObjectClass']) { $DetailClasses = @($Detail.PSObject.Properties['ObjectClass'].Value) }
            if ($DetailClasses -contains 'user') { $ObjectClass = 'User' }
            elseif ($DetailClasses -contains 'computer') { $ObjectClass = 'Computer' }
            elseif ($DetailClasses -contains 'group') { $ObjectClass = 'Group' }
            if ($null -ne $Detail.PSObject.Properties['Enabled'] -and $null -ne $Detail.PSObject.Properties['Enabled'].Value) { $Enabled = [bool]$Detail.PSObject.Properties['Enabled'].Value }
            if ($null -ne $Detail.PSObject.Properties['adminCount'] -and $null -ne $Detail.PSObject.Properties['adminCount'].Value) { $AdminCount = [int]$Detail.PSObject.Properties['adminCount'].Value }
            if ($null -ne $Detail.PSObject.Properties['PasswordNeverExpires'] -and $null -ne $Detail.PSObject.Properties['PasswordNeverExpires'].Value) { $PasswordNeverExpires = [bool]$Detail.PSObject.Properties['PasswordNeverExpires'].Value }
            if ($null -ne $Detail.PSObject.Properties['SID'] -and $null -ne $Detail.PSObject.Properties['SID'].Value) { $MemberSid = [string]$Detail.PSObject.Properties['SID'].Value }
            if ($null -eq $PasswordNeverExpires -and $null -ne $Detail.PSObject.Properties['UserAccountControl'] -and $null -ne $Detail.PSObject.Properties['UserAccountControl'].Value) {
                $PasswordNeverExpires = (([int64]$Detail.PSObject.Properties['UserAccountControl'].Value -band [int64]0x10000) -ne 0)
            }
            if ($null -eq $Enabled -and $null -ne $Detail.PSObject.Properties['UserAccountControl'] -and $null -ne $Detail.PSObject.Properties['UserAccountControl'].Value) {
                $Enabled = (([int64]$Detail.PSObject.Properties['UserAccountControl'].Value -band [int64]0x2) -eq 0)
            }
        }

        $CurrentPath = @($MembershipPath + $GroupIdentity)
        $MembershipType = 'Direct'
        if ($MembershipPath.Count -gt 0) { $MembershipType = 'Indirect' }
        $NormalizedMember = [PSCustomObject][ordered]@{
            Name                = $Name
            SamAccountName      = $SamAccountName
            ObjectClass         = $ObjectClass
            ObjectGUID          = $ObjectGuid
            DistinguishedName   = $DistinguishedName
            Enabled             = $Enabled
            AdminCount          = $AdminCount
            PasswordNeverExpires = $PasswordNeverExpires
            MemberType          = $ObjectClass
            MembershipType      = $MembershipType
            MembershipPath      = $CurrentPath
            SID                 = $MemberSid
            Resolved             = ($null -ne $Detail)
        }
        $NormalizedMember

        if ($ObjectClass -eq 'Group' -and -not [string]::IsNullOrWhiteSpace($DistinguishedName)) {
            Resolve-TechHubADGroupMembership `
                -GroupIdentity $DistinguishedName `
                -MembershipPath $CurrentPath `
                -VisitedGroups $VisitedGroups
        }
    }
}
