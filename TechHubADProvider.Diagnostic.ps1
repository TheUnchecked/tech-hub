# ============================================================
# TechHub.ActiveDirectory - Provider Test Harness Diagnostic
# NON MODIFICA ALCUN FILE
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TechHub.ActiveDirectory - PROVIDER HARNESS DIAGNOSTIC" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

try {

    # --------------------------------------------------------
    # 1. Repository root
    # --------------------------------------------------------

    $RepoRoot = (Get-Location).Path

    Write-Host "[1] Repository root" -ForegroundColor Yellow
    Write-Host $RepoRoot
    Write-Host ""

    # --------------------------------------------------------
    # 2. Module paths
    # --------------------------------------------------------

    $ModuleRoot = Join-Path `
        $RepoRoot `
        'powershell\modules\TechHub.ActiveDirectory'

    $ModuleManifest = Join-Path `
        $ModuleRoot `
        'TechHub.ActiveDirectory.psd1'

    $ProviderPath = Join-Path `
        $ModuleRoot `
        'Providers\ActiveDirectory\TechHubADProvider.ps1'

    $ConverterPath = Join-Path `
        $ModuleRoot `
        'Private\ConvertTo-TechHubADProviderObject.ps1'

    $FactoryPath = Join-Path `
        $ModuleRoot `
        'Public\New-AssessmentADProvider.ps1'

    Write-Host "[2] Paths" -ForegroundColor Yellow
    Write-Host "ModuleRoot:     $ModuleRoot"
    Write-Host "Manifest:       $ModuleManifest"
    Write-Host "Provider:       $ProviderPath"
    Write-Host "Converter:      $ConverterPath"
    Write-Host "Factory:        $FactoryPath"
    Write-Host ""

    # --------------------------------------------------------
    # 3. File existence
    # --------------------------------------------------------

    Write-Host "[3] File existence" -ForegroundColor Yellow

    [PSCustomObject][ordered]@{
        ModuleRoot = Test-Path -LiteralPath $ModuleRoot
        Manifest   = Test-Path -LiteralPath $ModuleManifest
        Provider   = Test-Path -LiteralPath $ProviderPath
        Converter  = Test-Path -LiteralPath $ConverterPath
        Factory    = Test-Path -LiteralPath $FactoryPath
    } | Format-List

    Write-Host ""

    # --------------------------------------------------------
    # 4. Remove loaded module
    # --------------------------------------------------------

    Write-Host "[4] Removing loaded module" -ForegroundColor Yellow

    Remove-Module `
        TechHub.ActiveDirectory `
        -Force `
        -ErrorAction SilentlyContinue

    Write-Host "OK"
    Write-Host ""

    # --------------------------------------------------------
    # 5. Check manifest
    # --------------------------------------------------------

    Write-Host "[5] Manifest inspection" -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $ModuleManifest)) {
        throw "Manifest NOT FOUND: $ModuleManifest"
    }

    $ManifestData = Test-ModuleManifest `
        -Path $ModuleManifest `
        -ErrorAction Stop

    $ManifestData |
        Select-Object `
            Name,
            Version,
            RootModule,
            Path,
            FunctionsToExport,
            ClassesToExport |
        Format-List

    Write-Host ""

    # --------------------------------------------------------
    # 6. Import module
    # --------------------------------------------------------

    Write-Host "[6] Importing module" -ForegroundColor Yellow

    Import-Module `
        $ModuleManifest `
        -Force `
        -ErrorAction Stop

    Write-Host "IMPORT OK" -ForegroundColor Green
    Write-Host ""

    # --------------------------------------------------------
    # 7. Loaded module
    # --------------------------------------------------------

    Write-Host "[7] Loaded module" -ForegroundColor Yellow

    $LoadedModule = Get-Module TechHub.ActiveDirectory

    if ($null -eq $LoadedModule) {
        throw "Module imported but Get-Module returned NULL."
    }

    $LoadedModule |
        Select-Object `
            Name,
            Version,
            Path,
            ModuleType |
        Format-List

    Write-Host ""

    # --------------------------------------------------------
    # 8. Exported commands
    # --------------------------------------------------------

    Write-Host "[8] Exported commands" -ForegroundColor Yellow

    Get-Command `
        -Module TechHub.ActiveDirectory |
        Select-Object `
            Name,
            CommandType,
            Source |
        Sort-Object Name |
        Format-Table -AutoSize

    Write-Host ""

    # --------------------------------------------------------
    # 9. Provider factory
    # --------------------------------------------------------

    Write-Host "[9] New-AssessmentADProvider" -ForegroundColor Yellow

    $Factory = Get-Command `
        New-AssessmentADProvider `
        -ErrorAction SilentlyContinue

    if ($null -eq $Factory) {
        throw "New-AssessmentADProvider is NOT available after module import."
    }

    $Factory |
        Select-Object `
            Name,
            CommandType,
            Source |
        Format-List

    Write-Host ""

    # --------------------------------------------------------
    # 10. Provider creation
    # --------------------------------------------------------

    Write-Host "[10] Creating provider" -ForegroundColor Yellow

    $Provider = New-AssessmentADProvider

    if ($null -eq $Provider) {
        throw "New-AssessmentADProvider returned NULL."
    }

    Write-Host "Type:   $($Provider.GetType().FullName)"
    Write-Host "Server: $($Provider.Server)"
    Write-Host ""

    # --------------------------------------------------------
    # 11. ActiveDirectory module
    # --------------------------------------------------------

    Write-Host "[11] Real ActiveDirectory module" -ForegroundColor Yellow

    $ADModule = Get-Module `
        -ListAvailable `
        -Name ActiveDirectory `
        -ErrorAction SilentlyContinue

    if ($null -eq $ADModule) {

        Write-Host `
            "REAL ActiveDirectory module: NOT INSTALLED" `
            -ForegroundColor Yellow
    }
    else {

        $ADModule |
            Select-Object `
                Name,
                Version,
                Path |
            Format-List
    }

    Write-Host ""

    # --------------------------------------------------------
    # 12. Test Pester-style mock visibility
    # --------------------------------------------------------

    Write-Host "[12] Defining temporary AD commands" -ForegroundColor Yellow

    function global:Get-ADDomain {
        param(
            [string]$Server,
            [string]$ErrorAction
        )

        [PSCustomObject]@{
            DNSRoot           = 'example.test'
            NetBIOSName       = 'EXAMPLE'
            DistinguishedName = 'DC=example,DC=test'
            DomainMode        = 'Windows2016Domain'
        }
    }

    function global:Get-ADForest {
        param(
            [string]$Server,
            [string]$ErrorAction
        )

        [PSCustomObject]@{
            Name       = 'example.test'
            ForestMode = 'Windows2016Forest'
            RootDomain = 'example.test'
            Domains    = @('example.test')
        }
    }

    function global:Get-ADDomainController {
        param(
            [string]$Filter,
            [string]$Server,
            [string]$ErrorAction
        )

        @(
            [PSCustomObject]@{
                Name = 'APP01'
            }
        )
    }

    function global:Get-ADObject {
        param(
            [string]$LDAPFilter,
            [string]$SearchBase,
            [string[]]$Properties,
            [string]$Server,
            [string]$ErrorAction
        )

        @(
            [PSCustomObject]@{
                Name = 'APP01'
                SamAccountName = 'APP01$'
                DistinguishedName = 'CN=APP01,DC=example,DC=test'
                ObjectGUID = [guid]'11111111-1111-1111-1111-111111111111'
                ObjectClass = @('top','computer')
                ObjectCategory = 'computer'
                UserAccountControl = 0
                'msDS-AllowedToDelegateTo' = @(
                    'HTTP/api.example.test'
                )
            }
        )
    }

    function global:Get-ADGroup {
        param(
            [string]$SearchBase,
            [string]$Filter,
            [string[]]$Properties,
            [string]$Server,
            [string]$ErrorAction
        )

        @(
            [PSCustomObject]@{
                Name = 'Domain Admins'
            }
        )
    }

    function global:Get-ADGroupMember {
        param(
            [string]$Identity,
            [string]$Server,
            [string]$ErrorAction
        )

        @(
            [PSCustomObject]@{
                Name = 'alice'
                SamAccountName = 'alice'
            }
        )
    }

    Write-Host "AD command stubs created."
    Write-Host ""

    # --------------------------------------------------------
    # 13. Verify commands
    # --------------------------------------------------------

    Write-Host "[13] AD command visibility" -ForegroundColor Yellow

    @(
        'Get-ADDomain'
        'Get-ADForest'
        'Get-ADDomainController'
        'Get-ADObject'
        'Get-ADGroup'
        'Get-ADGroupMember'
    ) | ForEach-Object {

        $Command = Get-Command $_ -ErrorAction SilentlyContinue

        if ($null -eq $Command) {
            Write-Host "$_ : MISSING" -ForegroundColor Red
        }
        else {
            Write-Host "$_ : OK" -ForegroundColor Green
        }
    }

    Write-Host ""

    # --------------------------------------------------------
    # 14. Direct provider call
    # --------------------------------------------------------

    Write-Host "[14] Direct GetDomainInformation()" -ForegroundColor Yellow

    $Result = $Provider.GetDomainInformation()

    if ($null -eq $Result) {
        throw "GetDomainInformation returned NULL."
    }

    $Result |
        Format-List *

    Write-Host ""

    # --------------------------------------------------------
    # 15. Result data
    # --------------------------------------------------------

    Write-Host "[15] Domain result data" -ForegroundColor Yellow

    if ($null -eq $Result.Data) {
        Write-Host "Data = NULL" -ForegroundColor Red
    }
    else {
        $Result.Data |
            Format-List *
    }

    Write-Host ""

    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " DIAGNOSTIC COMPLETED" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
}
catch {

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " DIAGNOSTIC FAILED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    Write-Host "Exception:" -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    Write-Host "Category:" -ForegroundColor Yellow
    Write-Host $_.CategoryInfo
    Write-Host ""

    Write-Host "Position:" -ForegroundColor Yellow
    Write-Host $_.InvocationInfo.PositionMessage
    Write-Host ""

    Write-Host "ScriptStackTrace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace
}
finally {

    Remove-Item Function:\Get-ADDomain `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item Function:\Get-ADForest `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item Function:\Get-ADDomainController `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item Function:\Get-ADObject `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item Function:\Get-ADGroup `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item Function:\Get-ADGroupMember `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Module `
        TechHub.ActiveDirectory `
        -Force `
        -ErrorAction SilentlyContinue
}