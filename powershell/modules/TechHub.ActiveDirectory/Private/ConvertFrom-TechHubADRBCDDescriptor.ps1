function ConvertFrom-TechHubADRBCDDescriptor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Descriptor
    )

    if ($null -eq $Descriptor) {
        throw 'The RBCD security descriptor is null.'
    }

    $SecurityDescriptor = $Descriptor
    if ($Descriptor -is [byte[]]) {
        $SecurityDescriptor = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
        $SecurityDescriptor.SetSecurityDescriptorBinaryForm($Descriptor)
    }

    if ($null -eq $SecurityDescriptor.PSObject.Methods['GetAccessRules']) {
        throw 'The RBCD descriptor does not expose GetAccessRules.'
    }

    $AccessRules = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    foreach ($Rule in @($AccessRules)) {
        $Sid = $null
        if ($null -ne $Rule.PSObject.Properties['IdentityReference']) {
            $IdentityReference = $Rule.PSObject.Properties['IdentityReference'].Value
            if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                $Sid = $IdentityReference.Value
            }
            elseif ($null -ne $IdentityReference) {
                $Sid = [string]$IdentityReference
            }
        }

        $IdentityReferenceValue = $null
        if ($null -ne $Rule.PSObject.Properties['IdentityReference'] -and
            $null -ne $Rule.PSObject.Properties['IdentityReference'].Value) {
            $IdentityReferenceValue = [string]$Rule.PSObject.Properties['IdentityReference'].Value
        }

        $AccessType = $null
        if ($null -ne $Rule.PSObject.Properties['AccessControlType']) {
            $AccessType = [string]$Rule.PSObject.Properties['AccessControlType'].Value
        }

        $AccessMask = $null
        if ($null -ne $Rule.PSObject.Properties['AccessMask']) {
            $AccessMask = $Rule.PSObject.Properties['AccessMask'].Value
        }
        elseif ($null -ne $Rule.PSObject.Properties['ActiveDirectoryRights']) {
            $AccessMask = [int64]$Rule.PSObject.Properties['ActiveDirectoryRights'].Value
        }

        $ObjectType = [guid]::Empty
        if ($null -ne $Rule.PSObject.Properties['ObjectType'] -and
            $null -ne $Rule.PSObject.Properties['ObjectType'].Value) {
            try {
                $ObjectType = [guid]$Rule.PSObject.Properties['ObjectType'].Value
            }
            catch {
                Write-Verbose -Message 'An ACE has an invalid ObjectType value.'
            }
        }

        [PSCustomObject][ordered]@{
            SID               = $Sid
            IdentityReference = $IdentityReferenceValue
            AccessType        = $AccessType
            AccessMask        = $AccessMask
            ObjectType        = $ObjectType
        }
    }
}
