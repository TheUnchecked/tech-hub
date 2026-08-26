#Requires -Version 5.1

Set-StrictMode -Version Latest

function ConvertTo-TechHubADProviderObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $Values = [ordered]@{
        Name                     = $null
        SamAccountName           = $null
        DistinguishedName        = $null
        ObjectGUID               = $null
        ObjectClass              = $null
        ObjectCategory           = $null

        # ----------------------------------------------------
        # Computer / OS attributes
        # ----------------------------------------------------

        OperatingSystem          = $null
        OperatingSystemVersion   = $null

        Enabled                  = $null
        UserAccountControl       = $null
        AdminCount               = $null
        PasswordNeverExpires     = $null

        ServicePrincipalName     = @()
        MemberOf                 = @()

        'msDS-AllowedToDelegateTo' = $null

        SID                      = $null
    }

    foreach ($PropertyName in @($Values.Keys)) {

        $Property = `
            $InputObject.PSObject.Properties[$PropertyName]

        if (
            $null -eq $Property -or
            $null -eq $Property.Value
        ) {
            continue
        }

        switch ($PropertyName) {

            'ObjectGUID' {

                try {

                    $Values[$PropertyName] = `
                        [guid]$Property.Value
                }
                catch {

                    Write-Verbose `
                        -Message `
                        'Provider received an invalid ObjectGUID.'
                }
            }

            'Enabled' {

                $Values[$PropertyName] = `
                    [bool]$Property.Value
            }

            'UserAccountControl' {

                try {

                    $Values[$PropertyName] = `
                        [int64]$Property.Value
                }
                catch {

                    Write-Verbose `
                        -Message `
                        'Provider received an invalid UserAccountControl.'
                }
            }

            'AdminCount' {

                try {

                    $Values[$PropertyName] = `
                        [int]$Property.Value
                }
                catch {

                    Write-Verbose `
                        -Message `
                        'Provider received an invalid AdminCount.'
                }
            }

            'PasswordNeverExpires' {

                $Values[$PropertyName] = `
                    [bool]$Property.Value
            }

            'ServicePrincipalName' {

                $Values[$PropertyName] = @(
                    $Property.Value |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$_
                            )
                        }
                )
            }

            'MemberOf' {

                $Values[$PropertyName] = @(
                    $Property.Value |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$_
                            )
                        }
                )
            }

            'msDS-AllowedToDelegateTo' {

                $DelegationTargets = @(
                    $Property.Value |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$_
                            )
                        }
                )

                if ($DelegationTargets.Count -gt 0) {

                    $Values[$PropertyName] = `
                        [string[]]$DelegationTargets
                }
            }

            # ------------------------------------------------
            # OS attributes
            # ------------------------------------------------

            'OperatingSystem' {

                $Values[$PropertyName] = `
                    [string]$Property.Value
            }

            'OperatingSystemVersion' {

                $Values[$PropertyName] = `
                    [string]$Property.Value
            }

            # ------------------------------------------------
            # Default string attributes
            # ------------------------------------------------

            default {

                $Values[$PropertyName] = `
                    [string]$Property.Value
            }
        }
    }

    # ========================================================
    # DERIVED VALUES
    # ========================================================

    if (
        $null -eq $Values.Enabled -and
        $null -ne $Values.UserAccountControl
    ) {

        $Values.Enabled = (
            ($Values.UserAccountControl -band [int64]0x2) -eq 0
        )
    }

    if (
        $null -eq $Values.PasswordNeverExpires -and
        $null -ne $Values.UserAccountControl
    ) {

        $Values.PasswordNeverExpires = (
            ($Values.UserAccountControl -band [int64]0x10000) -ne 0
        )
    }

    # ========================================================
    # NORMALIZED PROVIDER OBJECT
    # ========================================================

    [PSCustomObject][ordered]@{

        Name                     = $Values.Name

        SamAccountName           = $Values.SamAccountName

        DistinguishedName        = $Values.DistinguishedName

        ObjectGUID               = $Values.ObjectGUID

        ObjectClass              = $Values.ObjectClass

        ObjectCategory           = $Values.ObjectCategory

        OperatingSystem          = $Values.OperatingSystem

        OperatingSystemVersion   = $Values.OperatingSystemVersion

        Enabled                  = $Values.Enabled

        UserAccountControl       = $Values.UserAccountControl

        AdminCount               = $Values.AdminCount

        PasswordNeverExpires     = $Values.PasswordNeverExpires

        ServicePrincipalName     = $Values.ServicePrincipalName

        MemberOf                 = $Values.MemberOf

        'msDS-AllowedToDelegateTo' = `
            $Values.'msDS-AllowedToDelegateTo'

        SID                      = $Values.SID
    }
}