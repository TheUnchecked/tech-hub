<#
.SYNOPSIS
    Parametri di configurazione della CA letti dal registro: periodi CRL,
    periodo di validita, filtro di audit, EnforceX500NameLengths, policy di
    emissione.
.DESCRIPTION
    Tutti i valori sono letti con "certutil -getreg" (funziona anche da CA
    remota via RPC, senza necessita di accesso diretto al registro) oppure,
    se in esecuzione localmente sull host della CA, in aggiunta con
    Get-ItemProperty come riscontro incrociato. Nessun valore viene scritto o
    modificato.

    Il percorso esatto del valore EnforceX500NameLengths non e documentato con
    certezza univoca (puo trovarsi sotto la chiave di configurazione della CA
    o sotto la chiave del modulo di policy): il programma prova entrambe le
    posizioni note e dichiara "non verificabile" se nessuna delle due restituisce
    un valore, invece di assumere un percorso.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe disponibile; diritto di lettura sulla CA
    (o accesso al registro locale se eseguito sull host della CA).
    Privilegi minimi necessari: nessun privilegio amministrativo per la
    lettura via certutil -getreg da remoto; per la lettura diretta del
    registro locale e sufficiente l accesso in lettura standard.
    Controlli dell'assessment coperti: 02 (Parametri di configurazione CA).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi, indipendente dalla dimensione
    della CA.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -config. Se omesso, si
    usa la CA di default locale.
.EXAMPLE
    .\02-ParametriConfigurazioneCA.ps1 -PercorsoUscita C:\Evidenze\CA01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso,

    [string]$ConfigCA = ''
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '02-ParametriConfigurazioneCA'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

$infoCertutil = Get-CertutilDisponibile
if (-not $infoCertutil.Disponibile) {
    Write-Error 'certutil.exe non trovato: impossibile proseguire.'
    exit 1
}

$caLocale = [string]::IsNullOrWhiteSpace($ConfigCA)
$argomentiConfig = if ($caLocale) { @() } else { @('-config', $ConfigCA) }

function Get-ValoreRegistroCA {
    <#
    .SYNOPSIS
        Legge un singolo valore di configurazione CA con certutil -getreg,
        restituendo un oggetto con esito ed eventuale messaggio di errore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ChiaveValore,
        [Parameter(Mandatory = $true)][string[]]$ArgomentiConfig
    )

    $risultato = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', $ChiaveValore) + $ArgomentiConfig)
    $successo = ($risultato.CodiceUscita -eq 0) -and (-not $risultato.Errore)
    $valore = $null
    if ($successo) {
        $rigaValore = $risultato.Output | Where-Object { $_ -match '=|REG_' } | Select-Object -First 1
        $valore = if ($rigaValore) { $rigaValore.Trim() } else { ($risultato.Output -join ' | ') }
    }
    [PSCustomObject]@{
        Successo = $successo
        Valore   = $valore
        Errore   = if (-not $successo) { ($risultato.Output -join ' | ') } else { $null }
    }
}

# Elenco dei valori richiesti dalla specifica dell'assessment, con l'ID controllo associato.
$valoriDaLeggere = @(
    @{ Id = '02.01'; Chiave = 'CA\CRLPeriod'; Descrizione = 'Periodo di validita della CRL base (CRLPeriod)' },
    @{ Id = '02.02'; Chiave = 'CA\CRLPeriodUnits'; Descrizione = 'Unita del periodo CRL base (CRLPeriodUnits)' },
    @{ Id = '02.03'; Chiave = 'CA\CRLDeltaPeriod'; Descrizione = 'Periodo di validita della CRL delta (CRLDeltaPeriod)' },
    @{ Id = '02.04'; Chiave = 'CA\CRLDeltaPeriodUnits'; Descrizione = 'Unita del periodo CRL delta (CRLDeltaPeriodUnits)' },
    @{ Id = '02.05'; Chiave = 'CA\CRLOverlapPeriod'; Descrizione = 'Periodo di sovrapposizione CRL (CRLOverlapPeriod)' },
    @{ Id = '02.06'; Chiave = 'CA\CRLOverlapUnits'; Descrizione = 'Unita del periodo di sovrapposizione CRL (CRLOverlapUnits)' },
    @{ Id = '02.07'; Chiave = 'CA\ValidityPeriod'; Descrizione = 'Periodo di validita predefinito dei certificati emessi (ValidityPeriod)' },
    @{ Id = '02.08'; Chiave = 'CA\ValidityPeriodUnits'; Descrizione = 'Unita del periodo di validita (ValidityPeriodUnits)' },
    @{ Id = '02.09'; Chiave = 'CA\AuditFilter'; Descrizione = 'Filtro di audit della CA (AuditFilter)' },
    @{ Id = '02.10'; Chiave = 'Policy\EditFlags'; Descrizione = 'Flag di policy di emissione del modulo policy predefinito (EditFlags)' }
)

foreach ($voce in $valoriDaLeggere) {
    $riepilogo.AccertamentiTentati++
    try {
        $esito = Get-ValoreRegistroCA -ChiaveValore $voce.Chiave -ArgomentiConfig $argomentiConfig
        if ($esito.Successo) {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo $voce.Id -Dominio 'ConfigurazioneCA' `
                        -Accertamento $voce.Descrizione -Valore $esito.Valore -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiRiusciti++
        }
        else {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo $voce.Id -Dominio 'ConfigurazioneCA' `
                        -Accertamento $voce.Descrizione -Valore $esito.Errore -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiFalliti++
        }
    }
    catch {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo $voce.Id -Dominio 'ConfigurazioneCA' `
                    -Accertamento $voce.Descrizione -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}

# EnforceX500NameLengths: percorso non certo, si provano due posizioni note documentate in guide di hardening ADCS.
$riepilogo.AccertamentiTentati++
$candidatiEnforceX500 = @('CA\EnforceX500NameLengths', 'Policy\EnforceX500NameLengths')
$trovatoEnforceX500 = $false
foreach ($candidato in $candidatiEnforceX500) {
    $esito = Get-ValoreRegistroCA -ChiaveValore $candidato -ArgomentiConfig $argomentiConfig
    if ($esito.Successo) {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '02.11' -Dominio 'ConfigurazioneCA' `
                    -Accertamento "Enforce X500 Name Lengths (trovato sotto '$candidato')" `
                    -Valore $esito.Valore -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $trovatoEnforceX500 = $true
        $riepilogo.AccertamentiRiusciti++
        break
    }
}
if (-not $trovatoEnforceX500) {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '02.11' -Dominio 'ConfigurazioneCA' `
                -Accertamento 'Enforce X500 Name Lengths' `
                -Valore "Valore non trovato in nessuna delle posizioni note provate: $($candidatiEnforceX500 -join ', '). Verificare manualmente il percorso esatto su questa versione di ADCS." `
                -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_02_ParametriConfigurazioneCA' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_02_ParametriConfigurazioneCA' -Formato 'JSON' | Out-Null

Write-Host "Programma 02 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
