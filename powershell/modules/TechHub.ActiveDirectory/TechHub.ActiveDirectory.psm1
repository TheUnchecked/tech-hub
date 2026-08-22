#requires -Version 5.1

Set-StrictMode -Version Latest

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
