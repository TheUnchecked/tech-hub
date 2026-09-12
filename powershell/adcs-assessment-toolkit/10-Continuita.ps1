<#
.SYNOPSIS
    Continuità operativa: stato del servizio CA, evidenza dell'esistenza e
    della data delle copie di sicurezza, presenza di procedure documentate
    rilevabili automaticamente (limitata, per natura dell'accertamento).
.DESCRIPTION
    Lo stato del servizio e letto con Get-Service. L'evidenza di backup usa il
    modulo PowerShell "Windows Server Backup" (Get-WBSummary/Get-WBJob) tramite
    il caricamento automatico dei moduli: questo programma non chiama mai
    Import-Module (verbo non ammesso in questa raccolta). Se il modulo non è
    installato (Windows Server Backup non è sempre presente, ed è comunque
    solo uno dei possibili strumenti di backup usati per una CA), l'esito è
    "non verificabile" con motivazione, non un errore bloccante: l'assenza del
    modulo non significa necessariamente assenza di backup, potrebbe
    semplicemente indicare l'uso di un altro strumento (backup applicativo di
    terze parti, snapshot a livello di hypervisor, backup dell'intero server).

    L'esistenza di procedure documentate (piano di disaster recovery,
    procedura di ripristino CA, ecc.) non è un dato osservabile in modo
    affidabile da un programma automatico: viene dichiarata esplicitamente
    come accertamento da svolgere tramite intervista o ispezione manuale,
    come previsto per gli accertamenti privi di un metodo di sola lettura
    affidabile.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: nessuno oltre a PowerShell; modulo "Windows Server Backup"
    (facoltativo) per l'evidenza di backup tramite quello specifico strumento.
    Privilegi minimi necessari: nessun privilegio amministrativo per
    Get-Service; Get-WBSummary/Get-WBJob richiedono di norma appartenenza al
    gruppo locale Backup Operators o Administrators sull host.
    Controlli dell'assessment coperti: 10 (Continuità). La sotto-voce
    "procedure documentate" è dichiarata "da verificare tramite intervista o
    ispezione manuale" per costruzione.
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.EXAMPLE
    .\10-Continuita.ps1 -PercorsoUscita C:\Evidenze\CA01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '10-Continuita'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# --- 10.01: stato del servizio CertSvc --------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $servizio = Get-Service -Name 'CertSvc' -ErrorAction Stop | Select-Object Name, Status, StartType
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '10.01' -Dominio 'Continuita' `
                -Accertamento 'Stato del servizio Servizi Certificati Active Directory (CertSvc)' `
                -Valore $servizio -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '10.01' -Dominio 'Continuita' `
                -Accertamento 'Stato del servizio CertSvc' -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 10.02: evidenza di backup tramite Windows Server Backup ---------------
$riepilogo.AccertamentiTentati++
try {
    $riepilogoBackup = Get-WBSummary -ErrorAction Stop
    $ultimiJob = $null
    try { $ultimiJob = Get-WBJob -Previous 5 -ErrorAction Stop | Select-Object JobType, StartTime, EndTime, JobState, HResult }
    catch { $ultimiJob = 'Get-WBJob non disponibile o nessun job precedente: dettaglio non ottenibile, solo riepilogo generale riportato.' }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '10.02' -Dominio 'Continuita' `
                -Accertamento 'Evidenza di backup tramite Windows Server Backup (se in uso su questo host)' `
                -Valore ([PSCustomObject]@{ RiepilogoGenerale = $riepilogoBackup; UltimiJob = $ultimiJob }) `
                -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '10.02' -Dominio 'Continuita' `
                -Accertamento 'Evidenza di backup tramite Windows Server Backup' `
                -Valore "Modulo Windows Server Backup non disponibile o interrogazione fallita: $($_.Exception.Message). Questo NON implica assenza di backup: potrebbe essere in uso un altro strumento (backup applicativo, snapshot hypervisor, soluzione di terze parti) non rilevabile da questo programma." `
                -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 10.03: procedure documentate (non osservabile automaticamente) -------
$riepilogo.AccertamentiTentati++
$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '10.03' -Dominio 'Continuita' `
            -Accertamento 'Esistenza di procedure documentate di disaster recovery/ripristino della CA' `
            -Valore 'Non osservabile in modo affidabile da un programma automatico. Da verificare tramite intervista al personale responsabile o ispezione manuale della documentazione (piano di disaster recovery, runbook di ripristino CA, registro delle prove di ripristino).' `
            -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
$riepilogo.AccertamentiFalliti++

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_10_Continuita' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_10_Continuita' -Formato 'JSON' | Out-Null

Write-Host "Programma 10 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
