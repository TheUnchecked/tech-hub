function ConvertTo-TechHubADProviderObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $Values = [ordered]@{
        Name                = $null
        SamAccountName      = $null
        DistinguishedName   = $null
        ObjectGUID          = $null
        ObjectClass         = $null
        ObjectCategory      = $null
        Enabled             = $null
        UserAccountControl  = $null
        AdminCount          = $null
        PasswordNeverExpires = $null
        ServicePrincipalName = @()
        MemberOf            = @()
        'msDS-AllowedToDelegateTo' = $null
        SID                 = $null
    }

    foreach ($PropertyName in @($Values.Keys)) {
        $Property = $InputObject.PSObject.Properties[$PropertyName]
        if ($null -eq $Property -or $null -eq $Property.Value) {
            continue
        }

        switch ($PropertyName) {
            'ObjectGUID' {
                try { $Values[$PropertyName] = [guid]$Property.Value } catch { Write-Verbose -Message 'Provider received an invalid ObjectGUID.' }
            }
            'Enabled' { $Values[$PropertyName] = [bool]$Property.Value }
            'UserAccountControl' { try { $Values[$PropertyName] = [int64]$Property.Value } catch { Write-Verbose -Message 'Provider received an invalid UserAccountControl.' } }
            'AdminCount' { try { $Values[$PropertyName] = [int]$Property.Value } catch { Write-Verbose -Message 'Provider received an invalid AdminCount.' } }
            'PasswordNeverExpires' { $Values[$PropertyName] = [bool]$Property.Value }
            'ServicePrincipalName' { $Values[$PropertyName] = @($Property.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
            'MemberOf' { $Values[$PropertyName] = @($Property.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
            'msDS-AllowedToDelegateTo' {
                $DelegationTargets = @($Property.Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($DelegationTargets.Count -gt 0) {
                    $Values[$PropertyName] = [string[]]$DelegationTargets
                }
            }
            default { $Values[$PropertyName] = [string]$Property.Value }
        }
    }

    if ($null -eq $Values.Enabled -and $null -ne $Values.UserAccountControl) {
        $Values.Enabled = (($Values.UserAccountControl -band [int64]0x2) -eq 0)
    }
    if ($null -eq $Values.PasswordNeverExpires -and $null -ne $Values.UserAccountControl) {
        $Values.PasswordNeverExpires = (($Values.UserAccountControl -band [int64]0x10000) -ne 0)
    }

    [PSCustomObject][ordered]@{
        Name                 = $Values.Name
        SamAccountName       = $Values.SamAccountName
        DistinguishedName    = $Values.DistinguishedName
        ObjectGUID           = $Values.ObjectGUID
        ObjectClass          = $Values.ObjectClass
        ObjectCategory       = $Values.ObjectCategory
        Enabled              = $Values.Enabled
        UserAccountControl   = $Values.UserAccountControl
        AdminCount           = $Values.AdminCount
        PasswordNeverExpires = $Values.PasswordNeverExpires
        ServicePrincipalName = $Values.ServicePrincipalName
        MemberOf             = $Values.MemberOf
        'msDS-AllowedToDelegateTo' = $Values.'msDS-AllowedToDelegateTo'
        SID                  = $Values.SID
    }
}
