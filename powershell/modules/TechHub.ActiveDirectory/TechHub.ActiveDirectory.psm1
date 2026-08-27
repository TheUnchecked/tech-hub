#Requires -Version 5.1

Set-StrictMode -Version Latest

# ============================================================
# TECHHUB.ACTIVEDIRECTORY MODULE LOADER
# ============================================================

$ModuleRoot = $PSScriptRoot

# ============================================================
# 1. CLASSES
# ============================================================

$ClassesPath = Join-Path `
    $ModuleRoot `
    'Classes'

if (Test-Path -LiteralPath $ClassesPath) {

    $ClassFiles = @(
        Get-ChildItem `
            -LiteralPath $ClassesPath `
            -Filter '*.ps1' `
            -File `
            -ErrorAction Stop |
            Sort-Object Name
    )

    foreach ($ClassFile in $ClassFiles) {

        . $ClassFile.FullName
    }
}

# ============================================================
# 2. PRIVATE FUNCTIONS
# ============================================================

$PrivatePath = Join-Path $ModuleRoot 'Private'

$PrivateFiles = @(
    Get-ChildItem `
        -LiteralPath $PrivatePath `
        -Filter '*.ps1' `
        -File `
        -ErrorAction Stop |
    Sort-Object Name
)

foreach ($PrivateFile in $PrivateFiles) {

    Write-Verbose "Loading private function: $($PrivateFile.Name)"

    . $PrivateFile.FullName
}

# ============================================================
# 3. PROVIDERS
# ============================================================

$ProviderPath = Join-Path `
    $ModuleRoot `
    'Providers\ActiveDirectory'

if (Test-Path -LiteralPath $ProviderPath) {

    $ProviderFiles = @(
        Get-ChildItem `
            -LiteralPath $ProviderPath `
            -Filter '*.ps1' `
            -File `
            -ErrorAction Stop |
            Sort-Object Name
    )

    foreach ($ProviderFile in $ProviderFiles) {

        try {

            . $ProviderFile.FullName

        }
        catch {

            throw (
                'Failed to load provider file [{0}]: {1}' -f
                $ProviderFile.Name,
                $_.Exception.Message
            )
        }
    }
}

# ============================================================
# 4. PUBLIC FUNCTIONS
# ============================================================

$PublicPath = Join-Path `
    $ModuleRoot `
    'Public'

if (Test-Path -LiteralPath $PublicPath) {

    $PublicFunctions = @(
        Get-ChildItem `
            -LiteralPath $PublicPath `
            -Filter '*.ps1' `
            -File `
            -ErrorAction Stop |
            Sort-Object Name
    )

    foreach ($PublicFunction in $PublicFunctions) {

        try {

            . $PublicFunction.FullName

        }
        catch {

            throw (
                'Failed to load public function file [{0}]: {1}' -f
                $PublicFunction.Name,
                $_.Exception.Message
            )
        }
    }
}
else {

    $PublicFunctions = @()
}

# ============================================================
# 5. EXPORT PUBLIC FUNCTIONS ONLY
# ============================================================

Export-ModuleMember `
    -Function $PublicFunctions.BaseName