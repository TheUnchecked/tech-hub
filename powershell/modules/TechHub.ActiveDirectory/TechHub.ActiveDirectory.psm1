#requires -Version 5.1

Set-StrictMode -Version Latest

# ============================================================
# TECHHUB.ACTIVEDIRECTORY MODULE LOADER
# ============================================================

$ModuleRoot = $PSScriptRoot

# ============================================================
# 1. CLASSES
# ============================================================

$ClassFiles = @(
    Get-ChildItem `
        -LiteralPath (Join-Path $ModuleRoot 'Classes') `
        -Filter '*.ps1' `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object Name
)

foreach ($ClassFile in $ClassFiles) {

    . $ClassFile.FullName
}

# ============================================================
# 2. PRIVATE FUNCTIONS
# ============================================================

$PrivatePath = Join-Path $ModuleRoot 'Private'

$PrivateFunctions = @(
    Get-ChildItem `
        -LiteralPath $PrivatePath `
        -Filter '*.ps1' `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object Name
)

foreach ($PrivateFunction in $PrivateFunctions) {

    . $PrivateFunction.FullName
}

# ============================================================
# 3. PROVIDERS
# ============================================================

$ProviderPath = Join-Path `
    $ModuleRoot `
    'Providers\ActiveDirectory'

$ProviderFiles = @(
    Get-ChildItem `
        -LiteralPath $ProviderPath `
        -Filter '*.ps1' `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object Name
)

foreach ($ProviderFile in $ProviderFiles) {

    . $ProviderFile.FullName
}

# ============================================================
# 4. PUBLIC FUNCTIONS
# ============================================================

$PublicPath = Join-Path $ModuleRoot 'Public'

$PublicFunctions = @(
    Get-ChildItem `
        -LiteralPath $PublicPath `
        -Filter '*.ps1' `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object Name
)

foreach ($PublicFunction in $PublicFunctions) {

    . $PublicFunction.FullName
}

# ============================================================
# 5. EXPORT PUBLIC FUNCTIONS ONLY
# ============================================================

Export-ModuleMember `
    -Function $PublicFunctions.BaseName