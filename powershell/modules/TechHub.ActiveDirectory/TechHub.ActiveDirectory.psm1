#requires -Version 5.1

Set-StrictMode -Version Latest

$ClassFiles = @(
    Get-ChildItem -Path "$PSScriptRoot/Classes/*.ps1" -File -ErrorAction SilentlyContinue
)

foreach ($ClassFile in $ClassFiles) {
    . $ClassFile.FullName
}

$ProviderFiles = @(
    Get-ChildItem -Path "$PSScriptRoot/Providers/ActiveDirectory/*.ps1" -File -ErrorAction SilentlyContinue
)

foreach ($ProviderFile in $ProviderFiles) {
    . $ProviderFile.FullName
}

$PrivateFunctions = @(
    Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -File -ErrorAction SilentlyContinue
)

foreach ($Function in $PrivateFunctions) {
    . $Function.FullName
}

$PublicFunctions = @(
    Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -File -ErrorAction SilentlyContinue
)

foreach ($Function in $PublicFunctions) {
    . $Function.FullName
}

Export-ModuleMember -Function $PublicFunctions.BaseName