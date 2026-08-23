class TechHubADProvider {
    [string]$Server
    [System.Collections.ArrayList]$Results

    TechHubADProvider([string]$ServerName) {
        $this.Server = $ServerName
        $this.Results = New-Object System.Collections.ArrayList
    }

    [object] NewResult([string]$Operation, [string]$Status, [object]$Data, [string]$ErrorType, [string]$ErrorMessage) {
        $Result = [PSCustomObject][ordered]@{
            Provider       = 'TechHubADProvider'
            Operation      = $Operation
            Status         = $Status
            Data           = @($Data)
            ErrorType      = $ErrorType
            ErrorMessage   = $ErrorMessage
            Server         = $this.Server
            IsReadOnly     = $true
        }
        [void]$this.Results.Add($Result)
        return $Result
    }

    [bool] HasActiveDirectoryModule() {
        return ($null -ne (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue))
    }

    [string] GetErrorType([System.Management.Automation.ErrorRecord]$ErrorRecord) {
        $Message = [string]$ErrorRecord.Exception.Message
        if ($Message -match '(?i)access is denied|access denied|unauthorized') { return 'AccessDenied' }
        if ($Message -match '(?i)not found|cannot find|identity.*not') { return 'ObjectNotFound' }
        if ($Message -match '(?i)server|domain controller|unreachable|network|timeout|RPC') { return 'ServerUnavailable' }
        if ($Message -match '(?i)LDAP|directory service') { return 'LdapError' }
        return 'ProviderError'
    }

    [object] GetProviderStatus() {
        if ($this.Results.Count -eq 0) {
            return [PSCustomObject][ordered]@{ Provider = 'TechHubADProvider'; Status = 'NotAvailable'; IsReadOnly = $true }
        }
        $Statuses = @($this.Results | ForEach-Object { $_.Status })
        $Status = 'Available'
        $AvailableCount = @($Statuses | Where-Object { $_ -eq 'Available' }).Count
        if ($Statuses -contains 'Error' -and $AvailableCount -gt 0) { $Status = 'Partial' }
        elseif ($Statuses -contains 'Error') { $Status = 'Error' }
        elseif ($Statuses -contains 'Partial') { $Status = 'Partial' }
        elseif ($Statuses -contains 'NotAvailable') { $Status = 'Partial' }
        return [PSCustomObject][ordered]@{ Provider = 'TechHubADProvider'; Status = $Status; IsReadOnly = $true }
    }

    [object] GetDomainInformation() {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetDomainInformation', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Parameters = @{ ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $Parameters.Server = $this.Server }
            $Data = Get-ADDomain @Parameters
            $DomainData = [PSCustomObject][ordered]@{ DNSRoot = $null; NetBIOSName = $null; DistinguishedName = $null; DomainMode = $null }
            foreach ($PropertyName in @('DNSRoot', 'NetBIOSName', 'DistinguishedName', 'DomainMode')) {
                if ($null -ne $Data.PSObject.Properties[$PropertyName]) { $DomainData.$PropertyName = $Data.PSObject.Properties[$PropertyName].Value }
            }
            return $this.NewResult('GetDomainInformation', 'Available', $DomainData, $null, $null)
        }
        catch {
            return $this.NewResult('GetDomainInformation', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }

    [object] GetForestInformation() {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetForestInformation', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Parameters = @{ ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $Parameters.Server = $this.Server }
            $Data = Get-ADForest @Parameters
            $ForestData = [PSCustomObject][ordered]@{ Name = $null; ForestMode = $null; RootDomain = $null; Domains = @() }
            foreach ($PropertyName in @('Name', 'ForestMode', 'RootDomain')) {
                if ($null -ne $Data.PSObject.Properties[$PropertyName]) { $ForestData.$PropertyName = $Data.PSObject.Properties[$PropertyName].Value }
            }
            if ($null -ne $Data.PSObject.Properties['Domains']) { $ForestData.Domains = @($Data.PSObject.Properties['Domains'].Value) }
            return $this.NewResult('GetForestInformation', 'Available', $ForestData, $null, $null)
        }
        catch {
            return $this.NewResult('GetForestInformation', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }

    [object] GetDomainControllers() {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetDomainControllers', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Parameters = @{ Filter = '*'; ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $Parameters.Server = $this.Server }
            $Data = @(Get-ADDomainController @Parameters | ForEach-Object { ConvertTo-TechHubADProviderObject -InputObject $_ })
            return $this.NewResult('GetDomainControllers', 'Available', $Data, $null, $null)
        }
        catch {
            return $this.NewResult('GetDomainControllers', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }

    [object] GetADObjects([string]$LdapFilter, [string]$SearchBase, [string[]]$Properties) {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetADObjects', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Parameters = @{ LDAPFilter = $LdapFilter; Properties = $Properties; ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $Parameters.Server = $this.Server }
            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $Parameters.SearchBase = $SearchBase }
            $Data = @(Get-ADObject @Parameters | ForEach-Object { ConvertTo-TechHubADProviderObject -InputObject $_ })
            return $this.NewResult('GetADObjects', 'Available', $Data, $null, $null)
        }
        catch {
            return $this.NewResult('GetADObjects', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }

    [object] GetGroups([string]$SearchBase, [string]$Filter) {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetGroups', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Parameters = @{ Filter = $(if ([string]::IsNullOrWhiteSpace($Filter)) { '*' } else { $Filter }); Properties = @('Name', 'SamAccountName', 'DistinguishedName', 'ObjectGUID', 'ObjectClass', 'ObjectCategory', 'MemberOf', 'AdminCount'); ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $Parameters.Server = $this.Server }
            if (-not [string]::IsNullOrWhiteSpace($SearchBase)) { $Parameters.SearchBase = $SearchBase }
            $Data = @(Get-ADGroup @Parameters | ForEach-Object { ConvertTo-TechHubADProviderObject -InputObject $_ })
            return $this.NewResult('GetGroups', 'Available', $Data, $null, $null)
        }
        catch {
            return $this.NewResult('GetGroups', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }

    [object] GetGroupMembers([string]$GroupIdentity) {
        if (-not $this.HasActiveDirectoryModule()) { return $this.NewResult('GetGroupMembers', 'NotAvailable', @(), 'ModuleUnavailable', 'The ActiveDirectory module is not available.') }
        try {
            $Data = @(Get-ADGroupMember -Identity $GroupIdentity -ErrorAction Stop | ForEach-Object { ConvertTo-TechHubADProviderObject -InputObject $_ })
            return $this.NewResult('GetGroupMembers', 'Available', $Data, $null, $null)
        }
        catch {
            return $this.NewResult('GetGroupMembers', 'Error', @(), $this.GetErrorType($_), $_.Exception.Message)
        }
    }
}
