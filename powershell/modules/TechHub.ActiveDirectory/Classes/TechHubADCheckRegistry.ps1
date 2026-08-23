class TechHubADCheckDefinition {
    [string]$CheckId
    [string]$Name
    [string]$Description
    [string]$Category
    [string]$Version
    [bool]$Enabled
    [bool]$IsReadOnly
    [string]$FunctionName
    [string[]]$RequiredProviders
    [string[]]$RequiredModules
    [string[]]$Tags

    TechHubADCheckDefinition(
        [string]$CheckId,
        [string]$Name,
        [string]$Description,
        [string]$Category,
        [string]$Version,
        [bool]$Enabled,
        [bool]$IsReadOnly,
        [string]$FunctionName,
        [string[]]$RequiredProviders,
        [string[]]$RequiredModules,
        [string[]]$Tags
    ) {
        $this.CheckId = $CheckId
        $this.Name = $Name
        $this.Description = $Description
        $this.Category = $Category
        $this.Version = $Version
        $this.Enabled = $Enabled
        $this.IsReadOnly = $IsReadOnly
        $this.FunctionName = $FunctionName
        $this.RequiredProviders = @($RequiredProviders)
        $this.RequiredModules = @($RequiredModules)
        $this.Tags = @($Tags)
    }
}

class TechHubADCheckRegistry {
    [System.Collections.ArrayList]$Definitions
    hidden [hashtable]$Index

    TechHubADCheckRegistry() {
        $this.Definitions = New-Object System.Collections.ArrayList
        $this.Index = @{}
    }

    [void] ValidateDefinition([object]$Definition) {
        if ($null -eq $Definition) {
            throw 'Check definition cannot be null.'
        }
        foreach ($PropertyName in @('CheckId', 'Name', 'Description', 'Category', 'Version', 'FunctionName', 'RequiredProviders', 'RequiredModules', 'Tags')) {
            if ($null -eq $Definition.PSObject.Properties[$PropertyName]) {
                throw ("Check definition is missing required property '{0}'." -f $PropertyName)
            }
        }
        foreach ($PropertyName in @('CheckId', 'Name', 'Description', 'Category', 'Version', 'FunctionName')) {
            if ([string]::IsNullOrWhiteSpace([string]$Definition.PSObject.Properties[$PropertyName].Value)) {
                throw ("Check definition property '{0}' cannot be empty." -f $PropertyName)
            }
        }
        if ($null -eq $Definition.PSObject.Properties['Enabled'] -or
            $null -eq $Definition.PSObject.Properties['IsReadOnly']) {
            throw 'Check definition must include Enabled and IsReadOnly metadata.'
        }
        if ($Definition.IsReadOnly -ne $true) {
            throw 'Active Directory assessment checks must be read-only.'
        }
    }

    [void] Register([object]$Definition) {
        $this.ValidateDefinition($Definition)
        $CheckId = [string]$Definition.CheckId
        if ($this.Index.ContainsKey($CheckId)) {
            throw ("A check with CheckId '{0}' is already registered." -f $CheckId)
        }
        $RegisteredDefinition = [TechHubADCheckDefinition]::new(
            $CheckId,
            [string]$Definition.Name,
            [string]$Definition.Description,
            [string]$Definition.Category,
            [string]$Definition.Version,
            [bool]$Definition.Enabled,
            [bool]$Definition.IsReadOnly,
            [string]$Definition.FunctionName,
            [string[]]$Definition.RequiredProviders,
            [string[]]$Definition.RequiredModules,
            [string[]]$Definition.Tags
        )
        $this.Index[$CheckId] = $RegisteredDefinition
        [void]$this.Definitions.Add($RegisteredDefinition)
    }

    [object] Get([string]$CheckId) {
        if ([string]::IsNullOrWhiteSpace($CheckId)) { return $null }
        if ($this.Index.ContainsKey($CheckId)) { return $this.Index[$CheckId] }
        return $null
    }

    [object[]] GetAll() {
        return @($this.Definitions)
    }

    [object[]] FindByCategory([string]$Category) {
        return @($this.Definitions | Where-Object { $_.Category -eq $Category })
    }

    [object[]] FindByProvider([string]$Provider) {
        return @($this.Definitions | Where-Object { $_.RequiredProviders -contains $Provider })
    }

    [void] SetEnabled([string]$CheckId, [bool]$Enabled) {
        $Definition = $this.Get($CheckId)
        if ($null -eq $Definition) {
            throw ("CheckId '{0}' is not registered." -f $CheckId)
        }
        $Definition.Enabled = $Enabled
    }
}
