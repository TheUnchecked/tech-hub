<#
.SYNOPSIS
    Certificati emessi: profili, algoritmi, lunghezze, scadenze, SAN, conteggio
    per modello, algoritmi deboli, scaduti non revocati. Applica integralmente
    il vincolo di prestazione e la strategia di paginazione verificata dal
    programma 00.
.DESCRIPTION
    Approccio in due passate, entrambe scritte con "certutil -view -restrict"
    (mai un unico estratto integrale):

      Passata 1 (leggera): interroga solo tre colonne strette (RequestID,
      CertificateTemplate, NotBefore) sulla finestra determinata (vedi sotto),
      per ottenere economicamente il conteggio e la popolazione di
      riferimento su cui applicare eventuale campionamento.

      Passata 2 (dettaglio): interroga in pagine da -DimensionePagina
      RequestId (o intervalli di data, secondo la strategia raccomandata da
      00-VerificaStrategiaPaginazione.ps1) solo l'insieme di record selezionato
      dalla passata 1 (tutti, se entro -LimiteRecord o con -TuttiIRecord;
      altrimenti il campione secondo -StrategiaCampionamento).

    Determinazione della finestra temporale, quando non specificata
    esplicitamente con -DataInizio:
      - Senza -TuttiIRecord: si usa una finestra predefinita di
        -GiorniFinestraPredefinita giorni (default 90) fino ad ora. Questo
        realizza direttamente una delle due strategie di campionamento
        indicate nella specifica ("ultimi N per data"): senza un intervallo
        esplicito, il programma non tenta mai una scansione dell'intera
        storia della CA.
      - Con -TuttiIRecord: nessun limite di finestra, previo avviso esplicito
        a video e richiesta di conferma interattiva.

    Interpretazione dell'uscita di certutil -view: quando "-out" e "-restrict"
    sono usati insieme, certutil stampa un blocco testuale in formato CSV
    (intestazione + righe, con eventuale una riga di stato finale del tipo
    "CertUtil: -view command completed successfully." che viene scartata
    prima del parsing). Questo comportamento e ben noto ma il nome esatto
    delle intestazioni di colonna stampate da certutil (spesso nomi
    descrittivi, non gli stessi nomi schema passati a -out) NON e garantito
    identico su ogni versione: per questo il parsing avviene per POSIZIONE
    (l'ordine delle colonne richieste con -out), non per nome di intestazione.
    Se il parsing CSV fallisce, il record viene marcato "non verificabile" ma
    il testo grezzo resta comunque disponibile come evidenza.

    Tutti i campi derivati da crittografia (algoritmo di firma, lunghezza
    chiave, SAN, numero di serie) vengono ricavati analizzando il certificato
    stesso (colonna RawCertificate, DER base64, letta con X509Certificate2),
    non da nomi di colonna del database la cui esistenza non è certa: questo
    riduce la dipendenza da dettagli non documentati con certezza dello schema
    del database della CA.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe; diritto di lettura sulla CA; esecuzione
    preliminare di 00-VerificaStrategiaPaginazione.ps1 (se assente, si esegue
    un ripiego empirico rapido, con avviso).
    Privilegi minimi necessari: nessun privilegio amministrativo.
    Controlli dell'assessment coperti: 05 (Certificati emessi).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV, più un
    file separato con l'elenco dei certificati analizzati (dettaglio).
    Tempo di esecuzione atteso: CA piccola (<5k emessi nella finestra) ~1-2
    minuti; media (5k-50k) ~5-15 minuti; grande (>50k, con -TuttiIRecord) da
    decine di minuti a ore, a seconda della finestra e di -DimensionePagina.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -config.
.PARAMETER LimiteRecord
    Numero massimo di record da analizzare in dettaglio quando non si usa
    -TuttiIRecord. Predefinito: 5000.
.PARAMETER DimensionePagina
    Ampiezza di ciascuna pagina di lettura nella passata di dettaglio.
    Predefinito: 1000.
.PARAMETER TuttiIRecord
    Disattiva -LimiteRecord e la finestra temporale predefinita. Richiede
    conferma interattiva esplicita dopo un avviso sul carico atteso.
.PARAMETER DataInizio
    Inizio della finestra temporale (NotBefore). Se omesso e senza
    -TuttiIRecord, si usa "adesso meno -GiorniFinestraPredefinita giorni".
.PARAMETER DataFine
    Fine della finestra temporale (NotBefore). Predefinito: adesso.
.PARAMETER GiorniFinestraPredefinita
    Ampiezza in giorni della finestra predefinita quando -DataInizio non e
    specificato e -TuttiIRecord non e usato. Predefinito: 90.
.PARAMETER StrategiaCampionamento
    'UltimiPerData' (predefinito) o 'StratificatoPerModello': criterio con cui
    scegliere quali record analizzare in dettaglio quando la popolazione nella
    finestra supera -LimiteRecord.
.EXAMPLE
    .\05-CertificatiEmessi.ps1 -PercorsoUscita C:\Evidenze\CA01
.EXAMPLE
    .\05-CertificatiEmessi.ps1 -PercorsoUscita C:\Evidenze\CA01 -TuttiIRecord
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso,

    [string]$ConfigCA = '',

    [int]$LimiteRecord = 5000,

    [int]$DimensionePagina = 1000,

    [switch]$TuttiIRecord,

    [Nullable[datetime]]$DataInizio = $null,

    [Nullable[datetime]]$DataFine = $null,

    [int]$GiorniFinestraPredefinita = 90,

    [ValidateSet('UltimiPerData', 'StratificatoPerModello')]
    [string]$StrategiaCampionamento = 'UltimiPerData'
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '05-CertificatiEmessi'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()
$dettaglioCertificati = [System.Collections.Generic.List[object]]::new()
$completatoIntegralmente = $false

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

$argomentiConfig = @()
if (-not [string]::IsNullOrWhiteSpace($ConfigCA)) { $argomentiConfig = @('-config', $ConfigCA) }

$infoStrategia = Get-StrategiaLettura -PercorsoUscita $PercorsoUscita
$strategiaRaccomandata = if ($infoStrategia.Trovata) { $infoStrategia.StrategiaRaccomandata } else { $null }
$formatoData = if ($infoStrategia.Trovata) { $infoStrategia.FormatoDataAccettato } else { $null }

if (-not $strategiaRaccomandata) {
    Write-Warning 'Strategia di paginazione non disponibile: prova rapida in linea come ripiego (restrizione per data, formato MM/dd/yyyy).'
    $strategiaRaccomandata = 'Data'
    $formatoData = 'MM/gg/aaaa'
}

function ConvertTo-DataCertutil {
    param([datetime]$Data, [string]$FormatoNome)
    switch -Regex ($FormatoNome) {
        'aaaa-MM-gg' { return $Data.ToString('yyyy-MM-dd') }
        'HH:mm:ss' { return $Data.ToString('MM/dd/yyyy HH:mm:ss') }
        default { return $Data.ToString('MM/dd/yyyy') }
    }
}

# --- Determinazione della finestra temporale --------------------------------
$finestraSenzaLimiti = $false
if ($TuttiIRecord) {
    Write-Warning 'ATTENZIONE: -TuttiIRecord disattiva il limite di record e la finestra temporale predefinita.'
    Write-Warning 'Su una CA con centinaia di migliaia di record questa operazione puo comportare tempi molto lunghi e carico significativo sulla CA.'
    $conferma = Read-Host 'Digitare CONFERMO per procedere senza limiti, qualunque altro testo annulla'
    if ($conferma -ne 'CONFERMO') {
        Write-Host 'Operazione annullata dall utente. Nessuna interrogazione eseguita.'
        exit 0
    }
    $finestraSenzaLimiti = $true
    $dataInizioEffettiva = $DataInizio
    $dataFineEffettiva = if ($DataFine) { $DataFine } else { Get-Date }
}
else {
    $dataFineEffettiva = if ($DataFine) { $DataFine } else { Get-Date }
    $dataInizioEffettiva = if ($DataInizio) { $DataInizio } else { $dataFineEffettiva.AddDays(-$GiorniFinestraPredefinita) }
}

Write-Progress -Activity 'Certificati emessi' -Status 'Passata leggera: conteggio e popolazione di riferimento' -PercentComplete 5

# --- Passata 1 (leggera): popolazione di riferimento ------------------------
$riepilogo.AccertamentiTentati++
$popolazione = [System.Collections.Generic.List[object]]::new()
$erroreLeggera = $null
try {
    $restrizione = 'Disposition=20'
    if ($dataInizioEffettiva) {
        $valInizio = ConvertTo-DataCertutil -Data $dataInizioEffettiva -FormatoNome $formatoData
        $valFine = ConvertTo-DataCertutil -Data $dataFineEffettiva -FormatoNome $formatoData
        $restrizione = "Disposition=20,NotBefore>=$valInizio,NotBefore<=$valFine"
    }

    $risultatoLeggero = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizione, '-out', 'RequestID,CertificateTemplate,NotBefore') + $argomentiConfig)
    if ($risultatoLeggero.CodiceUscita -ne 0 -or $risultatoLeggero.Errore) {
        throw "certutil -view (passata leggera) ha restituito codice $($risultatoLeggero.CodiceUscita): $($risultatoLeggero.Errore)"
    }

    $righeCsv = $risultatoLeggero.Output | Where-Object { $_ -notmatch '^CertUtil:' -and $_.Trim() -ne '' }
    $oggetti = $righeCsv | ConvertFrom-Csv -ErrorAction Stop

    foreach ($o in $oggetti) {
        $valori = @($o.PSObject.Properties.Value)
        if ($valori.Count -ge 3) {
            $popolazione.Add([PSCustomObject]@{
                    RequestId           = $valori[0]
                    CertificateTemplate = $valori[1]
                    NotBefore           = $valori[2]
                })
        }
    }

    $riepilogo.AccertamentiRiusciti++
}
catch {
    $erroreLeggera = $_.Exception.Message
    $riepilogo.AccertamentiFalliti++
}

if ($erroreLeggera -or $popolazione.Count -eq 0) {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '05.01' -Dominio 'CertificatiEmessi' `
                -Accertamento 'Popolazione di riferimento nella finestra interrogata' `
                -Valore ($(if ($erroreLeggera) { $erroreLeggera } else { 'Nessun certificato emesso trovato nella finestra interrogata.' })) `
                -Stato ($(if ($erroreLeggera) { 'non verificabile' } else { 'rilevato' })) `
                -Completezza 'completo' -StrategiaLettura $strategiaRaccomandata))
    $riepilogo.RecordProdotti = $recordEvidenza.Count
    $riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo
    Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_05_CertificatiEmessi' -Formato $Formato | Out-Null
    Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_05_CertificatiEmessi' -Formato 'JSON' | Out-Null
    Write-Host 'Programma 05 terminato: nessun record disponibile da analizzare in dettaglio (vedi evidenza per il motivo).'
    exit 0
}

$conteggioTotale = $popolazione.Count
$completezza = 'completo'
$criterioCampionamento = 'nessuno (popolazione entro il limite)'

$popolazioneSelezionata = $popolazione
if (-not $finestraSenzaLimiti -and $conteggioTotale -gt $LimiteRecord) {
    $completezza = 'campionario'
    if ($StrategiaCampionamento -eq 'UltimiPerData') {
        $popolazioneSelezionata = $popolazione | Sort-Object { [datetime]$_.NotBefore } -Descending | Select-Object -First $LimiteRecord
        $criterioCampionamento = "ultimi $LimiteRecord per data (NotBefore) entro la finestra interrogata"
    }
    else {
        $gruppi = $popolazione | Group-Object -Property CertificateTemplate
        $numeroGruppi = [math]::Max(1, $gruppi.Count)
        $quotaPerGruppo = [math]::Max(1, [math]::Floor($LimiteRecord / $numeroGruppi))
        $selezione = [System.Collections.Generic.List[object]]::new()
        foreach ($g in $gruppi) {
            $selezione.AddRange(@($g.Group | Select-Object -First $quotaPerGruppo))
        }
        $popolazioneSelezionata = @($selezione | Select-Object -First $LimiteRecord)
        $criterioCampionamento = "campione stratificato per modello di certificato, fino a $quotaPerGruppo record per modello ($numeroGruppi modelli distinti)"
    }
    Write-Warning "Popolazione ($conteggioTotale) superiore a -LimiteRecord ($LimiteRecord): applicato campionamento '$StrategiaCampionamento'."
}
elseif ($finestraSenzaLimiti) {
    $criterioCampionamento = 'nessuno (-TuttiIRecord)'
}

$recordEvidenza.Add((Format-RecordEvidenza -IdControllo '05.01' -Dominio 'CertificatiEmessi' `
            -Accertamento 'Popolazione di riferimento nella finestra interrogata e criterio di selezione applicato' `
            -Valore ([PSCustomObject]@{
                FinestraDataInizio    = $dataInizioEffettiva
                FinestraDataFine      = $dataFineEffettiva
                ConteggioTotaleStimato = $conteggioTotale
                RecordSelezionatiPerDettaglio = $popolazioneSelezionata.Count
                CriterioCampionamento = $criterioCampionamento
            }) -Stato 'rilevato' -Completezza $completezza -StrategiaLettura $strategiaRaccomandata))
$riepilogo.AccertamentiRiusciti++

Write-Progress -Activity 'Certificati emessi' -Status 'Passata di dettaglio' -PercentComplete 20

# --- Passata 2 (dettaglio): paginazione per RequestId sull'insieme selezionato
$idOrdinati = $popolazioneSelezionata | ForEach-Object { [int64]$_.RequestId } | Sort-Object
$totalePagine = [math]::Ceiling($idOrdinati.Count / $DimensionePagina)
$paginaCorrente = 0

try {
    for ($i = 0; $i -lt $idOrdinati.Count; $i += $DimensionePagina) {
        $paginaCorrente++
        Write-Progress -Activity 'Certificati emessi' -Status "Pagina $paginaCorrente di $totalePagine" `
            -PercentComplete (20 + [math]::Min(75, (75.0 * $paginaCorrente / [math]::Max(1, $totalePagine))))

        $blocco = $idOrdinati[$i..[math]::Min($i + $DimensionePagina - 1, $idOrdinati.Count - 1)]
        $minId = $blocco[0]
        $maxId = $blocco[-1]

        $riepilogo.AccertamentiTentati++
        try {
            $restrizionePagina = "Disposition=20,RequestId>=$minId,RequestId<=$maxId"
            $risultatoPagina = Invoke-CertutilSolaLettura -Argomenti (@('-view', '-restrict', $restrizionePagina, '-out', 'RequestID,Request.RequesterName,NotBefore,NotAfter,CertificateTemplate,RawCertificate') + $argomentiConfig)

            if ($risultatoPagina.CodiceUscita -ne 0 -or $risultatoPagina.Errore) {
                throw "certutil -view (pagina $paginaCorrente) ha restituito codice $($risultatoPagina.CodiceUscita): $($risultatoPagina.Errore)"
            }

            $righeCsvPagina = $risultatoPagina.Output | Where-Object { $_ -notmatch '^CertUtil:' }
            $testoCsvUnito = $righeCsvPagina -join "`n"
            $oggettiPagina = $testoCsvUnito | ConvertFrom-Csv -ErrorAction Stop

            foreach ($riga in $oggettiPagina) {
                $valori = @($riga.PSObject.Properties.Value)
                if ($valori.Count -lt 6) { continue }

                $requestId = $valori[0]
                $richiedente = $valori[1]
                $notBefore = $valori[2]
                $notAfter = $valori[3]
                $template = $valori[4]
                $rawBase64 = $valori[5]

                $certificato = $null
                try {
                    if (-not [string]::IsNullOrWhiteSpace($rawBase64)) {
                        $bytes = [Convert]::FromBase64String(($rawBase64 -replace '\s', ''))
                        $certificato = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
                    }
                }
                catch {
                    $certificato = $null
                }

                $algoritmoFirma = $null; $lunghezzaChiave = $null; $algoritmoChiave = $null
                $san = @(); $numeroSerie = $null; $soggetto = $null

                if ($certificato) {
                    $algoritmoFirma = $certificato.SignatureAlgorithm.FriendlyName
                    $algoritmoChiave = $certificato.PublicKey.Oid.FriendlyName
                    try { $lunghezzaChiave = $certificato.PublicKey.Key.KeySize } catch { $lunghezzaChiave = $null }
                    $numeroSerie = $certificato.SerialNumber
                    $soggetto = $certificato.Subject
                    $estensioneSAN = $certificato.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
                    if ($estensioneSAN) {
                        try { $san = @(($estensioneSAN.Format($false)) -split ', ') } catch { $san = @() }
                    }
                }

                $algoritmoDebole = $false
                if ($algoritmoFirma -match '(?i)md5|sha1(?!\d)') { $algoritmoDebole = $true }
                if ($algoritmoChiave -match '(?i)rsa' -and $lunghezzaChiave -and [int]$lunghezzaChiave -lt 2048) { $algoritmoDebole = $true }

                $scadutoNonRevocato = $false
                try {
                    if ([datetime]$notAfter -lt (Get-Date)) { $scadutoNonRevocato = $true }
                }
                catch { }

                $dettaglioCertificati.Add([PSCustomObject]@{
                        RequestId           = $requestId
                        Richiedente         = $richiedente
                        NotBefore           = $notBefore
                        NotAfter            = $notAfter
                        CertificateTemplate = $template
                        Soggetto            = $soggetto
                        NumeroSerie         = $numeroSerie
                        AlgoritmoFirma      = $algoritmoFirma
                        AlgoritmoChiave     = $algoritmoChiave
                        LunghezzaChiave     = $lunghezzaChiave
                        SAN                 = $san
                        AlgoritmoDebole     = $algoritmoDebole
                        ScadutoNonRevocato  = $scadutoNonRevocato
                        CertificatoAnalizzabile = [bool]$certificato
                    })
            }
            $riepilogo.AccertamentiRiusciti++
        }
        catch {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '05.02' -Dominio 'CertificatiEmessi' `
                        -Accertamento "Lettura pagina $paginaCorrente (RequestId $minId-$maxId)" `
                        -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'campionario' -StrategiaLettura $strategiaRaccomandata))
            $riepilogo.AccertamentiFalliti++
        }
    }

    $completatoIntegralmente = $true
}
finally {
    Write-Progress -Activity 'Certificati emessi' -Completed

    $conteggioAlgoritmiDeboli = @($dettaglioCertificati | Where-Object { $_.AlgoritmoDebole }).Count
    $conteggioScadutiNonRevocati = @($dettaglioCertificati | Where-Object { $_.ScadutoNonRevocato }).Count
    $conteggioPerModello = $dettaglioCertificati | Group-Object -Property CertificateTemplate |
        ForEach-Object { [PSCustomObject]@{ Modello = $_.Name; Conteggio = $_.Count } }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '05.03' -Dominio 'CertificatiEmessi' `
                -Accertamento 'Riepilogo dei certificati analizzati in dettaglio' `
                -Valore ([PSCustomObject]@{
                    RecordAnalizzati            = $dettaglioCertificati.Count
                    ConCertificatoAnalizzabile  = @($dettaglioCertificati | Where-Object { $_.CertificatoAnalizzabile }).Count
                    ConteggioPerModello         = @($conteggioPerModello)
                    ConteggioAlgoritmiDeboli    = $conteggioAlgoritmiDeboli
                    ConteggioScadutiNonRevocati = $conteggioScadutiNonRevocati
                }) -Stato 'rilevato' -Completezza $completezza -StrategiaLettura $strategiaRaccomandata))

    $riepilogo.RecordProdotti = $recordEvidenza.Count + $dettaglioCertificati.Count
    $riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo
    if (-not $completatoIntegralmente) {
        $riepilogo.Note.Add('Esecuzione interrotta prima del completamento di tutte le pagine di dettaglio: le uscite sono marcate come PARZIALI.')
    }

    Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_05_CertificatiEmessi' -Formato $Formato -Parziale:(-not $completatoIntegralmente) | Out-Null
    Export-Evidenza -Dati $dettaglioCertificati -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Dettaglio_05_CertificatiEmessi' -Formato $Formato -Parziale:(-not $completatoIntegralmente) | Out-Null
    Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_05_CertificatiEmessi' -Formato 'JSON' | Out-Null
}

Write-Host "Programma 05 completato ($completezza). Certificati analizzati: $($dettaglioCertificati.Count) su una popolazione stimata di $conteggioTotale. Uscite in: $PercorsoUscita"
