<#
.SYNOPSIS
    Registrazione eventi: filtro di audit della CA, dimensione e conservazione
    dei registri di sistema, sincronizzazione oraria, campione limitato di
    eventi di audit rilevanti per i Certificate Services.
.DESCRIPTION
    Le letture da Get-WinEvent sono sempre limitate per numero (-MaxEventi) e
    finestra temporale (-DataInizio/-DataFine), mai integrali.

    Non vengono usati i binari esterni auditpol.exe o w32tm.exe: pur essendo
    di sola interrogazione nello spirito della richiesta, non sono cmdlet
    PowerShell e restano quindi fuori dall'elenco di verbi/strumenti ammessi
    indicato per questa raccolta. Di conseguenza:
      - la policy di audit dettagliata del sistema operativo (sottocategorie)
        NON è verificabile con questo programma: va accertata tramite
        intervista o ispezione manuale (es. con auditpol.exe o Criteri di
        gruppo), come previsto esplicitamente per gli accertamenti privi di
        un metodo di sola lettura affidabile in PowerShell puro.
      - la sincronizzazione oraria è riportata solo tramite stato del
        servizio w32time e sorgente NTP configurata da registro, senza lo
        stato di sincronizzazione effettivo che fornirebbe w32tm /query.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe; diritto di lettura sui registri eventi
    (Security incluso: di norma richiede appartenenza al gruppo locale Event
    Log Readers o privilegi amministrativi per il registro Security).
    Privilegi minimi necessari: appartenenza a "Event Log Readers" per la
    lettura del registro Security; nessun privilegio amministrativo per gli
    altri registri.
    Controlli dell'assessment coperti: 08 (Registrazione eventi). La
    sottocategoria "policy di audit del sistema operativo" è dichiarata "da
    verificare tramite intervista o ispezione manuale".
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi fino a circa un minuto, in
    funzione di -MaxEventi e della finestra temporale.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -getreg per AuditFilter.
.PARAMETER DataInizio
    Inizio della finestra per la lettura eventi. Predefinito: 30 giorni fa.
.PARAMETER DataFine
    Fine della finestra per la lettura eventi. Predefinito: adesso.
.PARAMETER MaxEventi
    Numero massimo di eventi da leggere per ciascun registro/filtro.
    Predefinito: 500.
.EXAMPLE
    .\08-RegistrazioneEventi.ps1 -PercorsoUscita C:\Evidenze\CA01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso,

    [string]$ConfigCA = '',

    [datetime]$DataInizio = (Get-Date).AddDays(-30),

    [datetime]$DataFine = (Get-Date),

    [int]$MaxEventi = 500
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '08-RegistrazioneEventi'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

$argomentiConfig = @()
if (-not [string]::IsNullOrWhiteSpace($ConfigCA)) { $argomentiConfig = @('-config', $ConfigCA) }

# --- 08.01: filtro di audit della CA (AuditFilter) --------------------------
$riepilogo.AccertamentiTentati++
try {
    $risultato = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', 'CA\AuditFilter') + $argomentiConfig)
    if ($risultato.CodiceUscita -ne 0 -or $risultato.Errore) {
        throw "certutil -getreg CA\AuditFilter ha restituito codice $($risultato.CodiceUscita): $($risultato.Errore)"
    }
    $rigaValore = $risultato.Output | Where-Object { $_ -match '=|REG_' } | Select-Object -First 1
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.01' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Filtro di audit della CA (AuditFilter)' `
                -Valore ($(if ($rigaValore) { $rigaValore.Trim() } else { ($risultato.Output -join ' | ') })) `
                -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.01' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Filtro di audit della CA (AuditFilter)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 08.02: policy di audit del sistema operativo (nessun metodo di sola
#            lettura affidabile in PowerShell puro senza auditpol.exe) ------
$riepilogo.AccertamentiTentati++
$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.02' -Dominio 'RegistrazioneEventi' `
            -Accertamento 'Policy di audit dettagliata del sistema operativo (sottocategorie)' `
            -Valore 'Nessun metodo di sola lettura affidabile disponibile in PowerShell puro (richiederebbe auditpol.exe, escluso da questa raccolta). Da verificare tramite intervista o ispezione manuale (auditpol /get /category:* sull host, o revisione dei Criteri di gruppo applicati).' `
            -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
$riepilogo.AccertamentiFalliti++

# --- 08.03: dimensione e conservazione dei registri eventi ------------------
$riepilogo.AccertamentiTentati++
try {
    $registri = Get-WinEvent -ListLog 'Security', 'Application', 'System' -ErrorAction Stop |
        Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount, LogFilePath
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.03' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Dimensione e conservazione dei registri eventi Security/Application/System' `
                -Valore @($registri) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.03' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Dimensione e conservazione dei registri eventi Security/Application/System' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 08.04: sincronizzazione oraria (solo servizio + sorgente configurata) -
$riepilogo.AccertamentiTentati++
try {
    $servizioOra = Get-CimInstance -ClassName Win32_Service -Filter "Name='w32time'" -ErrorAction Stop |
        Select-Object Name, State, StartMode
    $sorgenteNTP = $null
    try {
        $sorgenteNTP = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop).NtpServer
    }
    catch { $sorgenteNTP = 'non leggibile dal registro locale' }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.04' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Stato del servizio di sincronizzazione oraria e sorgente NTP configurata (nessuno stato di sincronizzazione effettivo: richiederebbe w32tm.exe, escluso da questa raccolta)' `
                -Valore ([PSCustomObject]@{ Servizio = $servizioOra; SorgenteNTPConfigurata = $sorgenteNTP }) `
                -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.04' -Dominio 'RegistrazioneEventi' `
                -Accertamento 'Stato del servizio di sincronizzazione oraria' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 08.05: campione limitato di eventi di audit ADCS rilevanti ------------
# ID evento noti per Servizi Certificati (registro Security, categoria
# "Object Access > Certification Services", quando l'AuditFilter della CA e
# abilitato): 4886 richiesta certificato, 4887 certificato emesso,
# 4888 richiesta negata, 4889 modello aggiornato, 4890 impostazioni di
# sicurezza CA modificate, 4891 impostazione CA modificata,
# 4892 certificato CA modificato, 4896 righe eliminate dal database,
# 4898 modello caricato.
$riepilogo.AccertamentiTentati++
try {
    $idEventiADCS = @(4886, 4887, 4888, 4889, 4890, 4891, 4892, 4896, 4898)
    $eventi = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = $idEventiADCS
        StartTime = $DataInizio
        EndTime   = $DataFine
    } -MaxEvents $MaxEventi -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, Message

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.05' -Dominio 'RegistrazioneEventi' `
                -Accertamento "Campione di eventi di audit Certificate Services (registro Security, ID $($idEventiADCS -join ',')), finestra $DataInizio - $DataFine, max $MaxEventi eventi" `
                -Valore @($eventi) -Stato 'rilevato' -Completezza 'campionario' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch [Exception] {
    if ($_.Exception.Message -match '(?i)no events were found') {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.05' -Dominio 'RegistrazioneEventi' `
                    -Accertamento "Campione di eventi di audit Certificate Services nella finestra $DataInizio - $DataFine" `
                    -Valore 'Nessun evento trovato nella finestra e con i filtri indicati (questo puo indicare AuditFilter non abilitato, o semplicemente nessuna attivita nella finestra: vedere 08.01).' `
                    -Stato 'rilevato' -Completezza 'campionario' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiRiusciti++
    }
    else {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '08.05' -Dominio 'RegistrazioneEventi' `
                    -Accertamento 'Campione di eventi di audit Certificate Services' `
                    -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'campionario' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_08_RegistrazioneEventi' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_08_RegistrazioneEventi' -Formato 'JSON' | Out-Null

Write-Host "Programma 08 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
