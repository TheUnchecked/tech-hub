<#
.SYNOPSIS
    Verifica sperimentale della strategia di paginazione per l'interrogazione
    del database di emissione di una CA ADCS (Active Directory Certificate Services).
.DESCRIPTION
    Il comportamento di "certutil -view" nel restringere i risultati per
    intervallo di RequestId o per finestra temporale non è uniforme tra le
    versioni di Windows Server, e il formato data accettato da "-restrict"
    dipende da locale/versione. Questo programma non assume nulla: esegue
    prove reali su intervalli ridotti, confronta esito/tempo/coerenza, e scrive
    la strategia raccomandata in StrategiaPaginazione.json. Tutti gli altri
    programmi della raccolta che leggono il database della CA leggono questo
    file all'avvio invece di usare una strategia cablata nel codice.

    Solo certutil.exe da riga di comando viene usato per interrogare il
    database (nessun oggetto COM CertificateAuthority.View/Admin): i parametri
    numerici interni di quell'interfaccia (es. costanti SeekOperator) non sono
    documentati con certezza sufficiente per essere codificati senza rischio di
    comportamento non verificato, quindi non vengono usati in questa raccolta.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe disponibile sul sistema; diritto di lettura
    sulla CA (di norma sufficiente il diritto "Read" concesso a Utenti
    autenticati; non serve "Manage CA" né "Issue and Manage Certificates").
    Privilegi minimi necessari: nessun privilegio amministrativo richiesto per
    l'interrogazione in sé; se il servizio CertSvc gira su un host diverso da
    quello di esecuzione, serve solo raggiungibilità RPC/DCOM verso la CA.
    Controlli dell'assessment coperti: nessuno direttamente. È un prerequisito
    tecnico per i programmi 05, 06 e 08, che leggono volumi potenzialmente
    grandi dal database della CA o dal registro eventi.
    Formato di uscita: StrategiaPaginazione.json (sempre JSON, indipendentemente
    da -Formato, perché letto in modo strutturato dagli altri programmi) più i
    record di evidenza normalizzati nel formato scelto con -Formato.
    Tempo di esecuzione atteso: le prove sono su intervalli ridotti (non
    sull'intero database), quindi il tempo è sostanzialmente indipendente dalla
    dimensione della CA: CA piccola, media o grande ~10-60 secondi in totale.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite. Il programma non crea
    cartelle (nessun cmdlet con verbo New/Set è usato in questa raccolta).
.PARAMETER Formato
    Formato dei record di evidenza normalizzati: JSON o CSV. Il file
    StrategiaPaginazione.json viene comunque sempre scritto in JSON.
.PARAMETER ConfigCA
    Stringa di configurazione CA nel formato "NomeServer\NomeCA" da passare a
    certutil -config. Se omesso, certutil usa la CA di default locale.
.PARAMETER CampioneRequestId
    Ampiezza (numero di RequestId) dell'intervallo usato per la prova di
    paginazione per RequestId. Predefinito: 50.
.PARAMETER CampioneGiorni
    Ampiezza in giorni della finestra temporale usata per la prova di
    paginazione per data. Predefinito: 7.
.EXAMPLE
    .\00-VerificaStrategiaPaginazione.ps1 -PercorsoUscita C:\Evidenze\CA01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso,

    [string]$ConfigCA = '',

    [int]$CampioneRequestId = 50,

    [int]$CampioneGiorni = 7
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '00-VerificaStrategiaPaginazione'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()
$prove = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

$argomentiConfig = @()
if (-not [string]::IsNullOrWhiteSpace($ConfigCA)) {
    $argomentiConfig = @('-config', $ConfigCA)
}

Write-Progress -Activity 'Verifica strategia di paginazione' -Status 'Rilevamento ambiente' -PercentComplete 5

# --- Passo 1: rilevamento ambiente -----------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $infoCertutil = Get-CertutilDisponibile
    if (-not $infoCertutil.Disponibile) {
        throw 'certutil.exe non trovato nel PATH di sistema.'
    }

    $infoSO = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $versioneOS = "$($infoSO.Caption) $($infoSO.Version) (Build $($infoSO.BuildNumber))"

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.01' -Dominio 'Ambiente' `
                -Accertamento 'Disponibilita e versione certutil.exe / sistema operativo' `
                -Valore ([PSCustomObject]@{
                    CertutilDisponibile = $infoCertutil.Disponibile
                    VersioneCertutil    = $infoCertutil.Versione
                    VersioneOS          = $versioneOS
                }) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.01' -Dominio 'Ambiente' `
                -Accertamento 'Disponibilita e versione certutil.exe / sistema operativo' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
    Write-Error "Impossibile proseguire senza certutil.exe: $($_.Exception.Message)"
    $riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo
    Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_00_VerificaStrategiaPaginazione' -Formato $Formato | Out-Null
    Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_00_VerificaStrategiaPaginazione' -Formato 'JSON' | Out-Null
    exit 1
}

# Nome CA attiva (per riferimento nell'uscita, letto dal registro tramite certutil -getreg, sola lettura)
$riepilogo.AccertamentiTentati++
$nomeCAAttiva = 'sconosciuto'
try {
    $risultatoNomeCA = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', 'CA\CommonName') + $argomentiConfig)
    if ($risultatoNomeCA.CodiceUscita -eq 0) {
        $rigaValore = $risultatoNomeCA.Output | Where-Object { $_ -match 'Value|REG_SZ' } | Select-Object -First 3
        $nomeCAAttiva = ($risultatoNomeCA.Output -join ' | ')
    }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.02' -Dominio 'Ambiente' `
                -Accertamento 'Nome CA interrogata (certutil -getreg CA\CommonName)' `
                -Valore $nomeCAAttiva -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.02' -Dominio 'Ambiente' `
                -Accertamento 'Nome CA interrogata (certutil -getreg CA\CommonName)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

Write-Progress -Activity 'Verifica strategia di paginazione' -Status 'Individuazione intervallo di prova' -PercentComplete 20

# --- Passo 2: individuazione di un piccolo intervallo di prova -------------
# Si usa una finestra temporale molto stretta e recente (ultimi CampioneGiorni
# giorni) per ottenere economicamente un piccolo insieme di RequestId reali da
# cui derivare l'intervallo di prova, evitando qualunque scansione integrale.
$formatiDataDaProvare = @(
    @{ Nome = 'MM/gg/aaaa'; Formatta = { param($d) $d.ToString('MM/dd/yyyy') } },
    @{ Nome = 'aaaa-MM-gg'; Formatta = { param($d) $d.ToString('yyyy-MM-dd') } },
    @{ Nome = 'MM/gg/aaaa HH:mm:ss'; Formatta = { param($d) $d.ToString('MM/dd/yyyy HH:mm:ss') } }
)

$formatoDataFunzionante = $null
$dataInizioCampione = (Get-Date).AddDays(-$CampioneGiorni)
$dataFineCampione = Get-Date
$righeCampioneData = @()

foreach ($candidato in $formatiDataDaProvare) {
    $riepilogo.AccertamentiTentati++
    $valoreInizio = & $candidato.Formatta $dataInizioCampione
    $valoreFine = & $candidato.Formatta $dataFineCampione
    $restrizione = "Disposition=20,NotBefore>=$valoreInizio,NotBefore<=$valoreFine"

    $risultato = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizione, '-out', 'RequestID,NotBefore') + $argomentiConfig)

    $successo = ($risultato.CodiceUscita -eq 0) -and ($null -eq $risultato.Errore) -and
                (-not ($risultato.Output -join "`n" | Select-String -Pattern 'non è valido|is not valid|errore di sintassi|syntax error' -Quiet))

    $prove.Add([PSCustomObject]@{
            Prova           = "FormatoData:$($candidato.Nome)"
            Restrizione     = $restrizione
            Successo        = [bool]$successo
            CodiceUscita    = $risultato.CodiceUscita
            DurataMs        = [math]::Round($risultato.DurataMs, 1)
            NumeroRighe     = if ($successo) { @($risultato.Output | Select-String -Pattern '^RequestID').Count } else { 0 }
            EstrattoOutput  = ($risultato.Output | Select-Object -First 5) -join ' / '
        })

    if ($successo -and -not $formatoDataFunzionante) {
        $formatoDataFunzionante = $candidato.Nome
        $righeCampioneData = $risultato.Output
    }

    if ($successo) { $riepilogo.AccertamentiRiusciti++ } else { $riepilogo.AccertamentiFalliti++ }
}

$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.03' -Dominio 'Paginazione' `
            -Accertamento 'Formato data accettato da certutil -restrict su questo sistema' `
            -Valore ($(if ($formatoDataFunzionante) { $formatoDataFunzionante } else { 'nessun formato provato ha funzionato' })) `
            -Stato ($(if ($formatoDataFunzionante) { 'rilevato' } else { 'non verificabile' })) `
            -Completezza 'campionario' -StrategiaLettura 'n/d'))

Write-Progress -Activity 'Verifica strategia di paginazione' -Status 'Prova A - paginazione per RequestId' -PercentComplete 45

# --- Passo 3: prova A - paginazione per RequestId ---------------------------
# Deriva un intervallo di RequestId reale dal campione per data appena ottenuto
# (se disponibile), altrimenti usa un intervallo di fallback dichiarato come tale.
$riepilogo.AccertamentiTentati++
$estremiRequestId = $null
try {
    $numeriRequestId = @()
    foreach ($riga in $righeCampioneData) {
        if ($riga -match '^\s*RequestID\s*=\s*"?(\d+)"?') {
            $numeriRequestId += [int]$Matches[1]
        }
        elseif ($riga -match '^\s*"(\d+)"') {
            $numeriRequestId += [int]$Matches[1]
        }
    }
    if ($numeriRequestId.Count -ge 2) {
        $estremiRequestId = @{ Min = ($numeriRequestId | Measure-Object -Minimum).Minimum; Max = ($numeriRequestId | Measure-Object -Maximum).Maximum }
    }
}
catch {
    $estremiRequestId = $null
}

if (-not $estremiRequestId) {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.04a' -Dominio 'Paginazione' `
                -Accertamento 'Individuazione intervallo RequestId di prova dal campione per data' `
                -Valore 'Nessun RequestId estratto dal campione per data; prova per RequestId non eseguita.' `
                -Stato 'non verificabile' -Completezza 'campionario' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
    $successoRequestId = $false
    $prove.Add([PSCustomObject]@{
            Prova          = 'Paginazione:RequestId'
            Restrizione    = 'non eseguita (nessun RequestId di riferimento disponibile)'
            Successo       = $false
            CodiceUscita   = $null
            DurataMs       = $null
            NumeroRighe    = 0
            EstrattoOutput = ''
        })
}
else {
    $inizioIntervallo = [math]::Max(0, $estremiRequestId.Min - [math]::Floor($CampioneRequestId / 2))
    $fineIntervallo = $estremiRequestId.Max + [math]::Ceiling($CampioneRequestId / 2)
    $restrizioneRequestId = "Disposition=20,RequestId>=$inizioIntervallo,RequestId<=$fineIntervallo"

    $risultatoRequestId = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizioneRequestId, '-out', 'RequestID,CertificateTemplate') + $argomentiConfig)
    $successoRequestId = ($risultatoRequestId.CodiceUscita -eq 0) -and ($null -eq $risultatoRequestId.Errore) -and
                          (-not ($risultatoRequestId.Output -join "`n" | Select-String -Pattern 'non è valido|is not valid|errore di sintassi|syntax error' -Quiet))

    $prove.Add([PSCustomObject]@{
            Prova          = 'Paginazione:RequestId'
            Restrizione    = $restrizioneRequestId
            Successo       = [bool]$successoRequestId
            CodiceUscita   = $risultatoRequestId.CodiceUscita
            DurataMs       = [math]::Round($risultatoRequestId.DurataMs, 1)
            NumeroRighe    = if ($successoRequestId) { @($risultatoRequestId.Output | Select-String -Pattern '^RequestID').Count } else { 0 }
            EstrattoOutput = ($risultatoRequestId.Output | Select-Object -First 5) -join ' / '
        })

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.04' -Dominio 'Paginazione' `
                -Accertamento 'Prova di restrizione per intervallo di RequestId' `
                -Valore $restrizioneRequestId -Stato ($(if ($successoRequestId) { 'rilevato' } else { 'non verificabile' })) `
                -Completezza 'campionario' -StrategiaLettura 'n/d'))

    if ($successoRequestId) { $riepilogo.AccertamentiRiusciti++ } else { $riepilogo.AccertamentiFalliti++ }
}
$riepilogo.AccertamentiTentati++

Write-Progress -Activity 'Verifica strategia di paginazione' -Status 'Prova B - selezione colonne' -PercentComplete 70

# --- Passo 4: prova selezione esplicita delle colonne -----------------------
# Confronta il tempo/volume di una query con elenco colonne ridotto rispetto
# a una query analoga senza restrizione di colonne (stesso intervallo dati).
$riepilogo.AccertamentiTentati++
$restrizioneBase = "Disposition=20,NotBefore>=$(& $formatiDataDaProvare[0].Formatta $dataInizioCampione),NotBefore<=$(& $formatiDataDaProvare[0].Formatta $dataFineCampione)"

$conColonne = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizioneBase, '-out', 'RequestID') + $argomentiConfig)
$senzaColonne = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizioneBase) + $argomentiConfig)

$prove.Add([PSCustomObject]@{
        Prova          = 'SelezioneColonne:conColonneRidotte'
        Restrizione    = $restrizioneBase
        Successo       = ($conColonne.CodiceUscita -eq 0)
        CodiceUscita   = $conColonne.CodiceUscita
        DurataMs       = [math]::Round($conColonne.DurataMs, 1)
        NumeroRighe    = @($conColonne.Output).Count
        EstrattoOutput = ($conColonne.Output | Select-Object -First 3) -join ' / '
    })
$prove.Add([PSCustomObject]@{
        Prova          = 'SelezioneColonne:senzaRestrizioneColonne'
        Restrizione    = $restrizioneBase
        Successo       = ($senzaColonne.CodiceUscita -eq 0)
        CodiceUscita   = $senzaColonne.CodiceUscita
        DurataMs       = [math]::Round($senzaColonne.DurataMs, 1)
        NumeroRighe    = @($senzaColonne.Output).Count
        EstrattoOutput = ($senzaColonne.Output | Select-Object -First 3) -join ' / '
    })

$riduzioneVolume = if ($senzaColonne.Output) {
    $bytesConColonne = ([string]($conColonne.Output -join "`n")).Length
    $bytesSenzaColonne = ([string]($senzaColonne.Output -join "`n")).Length
    if ($bytesSenzaColonne -gt 0) { [math]::Round(100 - (100.0 * $bytesConColonne / $bytesSenzaColonne), 1) } else { $null }
}
else { $null }

$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.05' -Dominio 'Paginazione' `
            -Accertamento 'Effetto della selezione esplicita delle colonne (-out) sul volume trasferito' `
            -Valore ([PSCustomObject]@{ RiduzionePercentualeVolume = $riduzioneVolume; DurataConColonneMs = [math]::Round($conColonne.DurataMs, 1); DurataSenzaColonneMs = [math]::Round($senzaColonne.DurataMs, 1) }) `
            -Stato 'rilevato' -Completezza 'campionario' -StrategiaLettura 'n/d'))
$riepilogo.AccertamentiRiusciti++

Write-Progress -Activity 'Verifica strategia di paginazione' -Status 'Determinazione raccomandazione' -PercentComplete 90

# --- Passo 5: determinazione della strategia raccomandata -------------------
$strategiaRaccomandata =
    if ($successoRequestId -and $formatoDataFunzionante) { 'RequestId' }
    elseif ($formatoDataFunzionante) { 'Data' }
    elseif ($successoRequestId) { 'RequestId' }
    else { 'NessunaAffidabile' }

$note = [System.Collections.Generic.List[string]]::new()
if ($strategiaRaccomandata -eq 'NessunaAffidabile') {
    $note.Add('Nessuna delle due strategie di restrizione ha superato la prova su questo sistema. I programmi 05/06/08 devono avvisare esplicitamente e operare con la massima cautela (campione minimo, mai -TuttiIRecord senza ulteriore verifica manuale).')
}
if ($strategiaRaccomandata -eq 'RequestId' -and -not $formatoDataFunzionante) {
    $note.Add('La restrizione per data non ha funzionato con nessuno dei formati provati: usare solo RequestId per la paginazione; le finestre -DataInizio/-DataFine andranno applicate come filtro lato client sui risultati, non come restrizione certutil.')
}
if (-not $successoRequestId -and $formatoDataFunzionante) {
    $note.Add('La restrizione per RequestId non ha funzionato: usare solo la paginazione per data.')
}

$stimaDimensioneDB = [PSCustomObject]@{
    Tipo   = 'stima approssimata, non conteggio esatto'
    Metodo = "numero di record emessi (Disposition=20) nella finestra di $CampioneGiorni giorni usata come campione"
    RecordNellaFinestraCampione = if ($righeCampioneData) { @($righeCampioneData | Select-String -Pattern '^RequestID').Count } else { 'non determinato' }
}

$strategiaJson = [PSCustomObject]@{
    Timestamp             = (Get-Date).ToString('o')
    NomeHost              = $env:COMPUTERNAME
    ConfigCA              = $(if ([string]::IsNullOrWhiteSpace($ConfigCA)) { 'CA locale di default' } else { $ConfigCA })
    NomeCARiferimento     = $nomeCAAttiva
    VersioneOS            = $versioneOS
    VersioneCertutil      = $infoCertutil.Versione
    FormatoDataAccettato  = $formatoDataFunzionante
    StimaDimensioneDB     = $stimaDimensioneDB
    Prove                 = $prove
    StrategiaRaccomandata = $strategiaRaccomandata
    Note                  = $note
}

Export-Evidenza -Dati $strategiaJson -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'StrategiaPaginazione' -Formato 'JSON' | Out-Null

$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '00.06' -Dominio 'Paginazione' `
            -Accertamento 'Strategia di paginazione raccomandata per i programmi successivi' `
            -Valore $strategiaRaccomandata -Stato 'rilevato' -Completezza 'campionario' -StrategiaLettura $strategiaRaccomandata))
$riepilogo.AccertamentiRiusciti++
$riepilogo.RecordProdotti = $recordEvidenza.Count

Write-Progress -Activity 'Verifica strategia di paginazione' -Completed

$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_00_VerificaStrategiaPaginazione' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_00_VerificaStrategiaPaginazione' -Formato 'JSON' | Out-Null

Write-Host "Strategia raccomandata: $strategiaRaccomandata"
Write-Host "Uscite scritte in: $PercorsoUscita"
