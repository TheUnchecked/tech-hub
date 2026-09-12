#requires -Version 5.1

Set-StrictMode -Version Latest

$PublicFunctions = @(
    Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue
)

foreach ($Function in $PublicFunctions) {
    . $Function.FullName
}

Export-ModuleMember -Function $PublicFunctions.BaseName