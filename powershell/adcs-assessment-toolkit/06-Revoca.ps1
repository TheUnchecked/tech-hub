<#
.SYNOPSIS
    Revoca: punti di distribuzione CRL/AIA configurati, raggiungibilità di
    base, data di emissione e di prossimo aggiornamento della CRL corrente,
    freschezza, risposta al controllo di revoca (inclusa OCSP se presente in
    AIA). Legge solo i metadati di intestazione della CRL, senza enumerare le
    singole voci revocate, salvo -MostraVociRevocate esplicito.
.DESCRIPTION
    Fonti di sola lettura usate:
      - certutil -getreg CA\CRLPublicationURLs / CA\CACertPublicationURLs:
        elenco configurato dei punti di pubblicazione (URL o percorso file),
        con un flag numerico di prefisso (formato "<flag>:<percorso o URL>",
        ben documentato nelle guide di configurazione ADCS). Il significato
        dei singoli bit del flag è riportato secondo l'interpretazione
        comunemente documentata (pubblicazione su file locale, aggiunta alla
        estensione CDP/AIA del certificato, ecc.); il valore grezzo resta
        comunque disponibile.
      - certutil -ca.cert / certutil -ca.crl: recuperano rispettivamente il
        certificato corrente della CA e la CRL correntemente pubblicata,
        scrivendoli solo dentro -PercorsoUscita (uso del verbo Export/-out
        limitato esclusivamente alla cartella di uscita, come richiesto).
        Funzionano sia in locale sia con -ConfigCA verso una CA remota.
      - certutil -dump sulla CRL recuperata, per i soli metadati di
        intestazione (emittente, data di emissione, prossimo aggiornamento,
        numero di CRL). L'etichetta testuale esatta usata da certutil per
        "This Update"/"Next Update" non è documentata con piena certezza in
        ogni versione: il parsing prova più varianti note e dichiara "non
        verificabile" per il singolo campo (non per l'intero accertamento) se
        nessuna corrisponde, mantenendo comunque il testo grezzo come prova.
      - certutil -verify -urlfetch sul certificato CA recuperato: esercita la
        validazione della catena incluso il recupero di CRL/OCSP indicati in
        AIA, restituendo un riscontro di raggiungibilità/validità senza che
        questo programma effettui direttamente chiamate HTTP proprie.
      - Test-NetConnection per un riscontro aggiuntivo di raggiungibilità di
        rete (solo verifica di porta) verso gli host HTTP/LDAP configurati.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe; per -ConfigCA remoto, raggiungibilità
    RPC/DCOM verso la CA; per la verifica di rete, raggiungibilità verso gli
    endpoint CDP/AIA configurati (porte 80/443/389 secondo il tipo di URL).
    Privilegi minimi necessari: nessun privilegio amministrativo.
    Controlli dell'assessment coperti: 06 (Revoca).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi fino a circa un minuto, dominato
    dai tempi di rete di certutil -verify -urlfetch se gli endpoint sono lenti
    o irraggiungibili (certutil applica comunque un proprio timeout interno).
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite (anche i file temporanei
    del certificato CA e della CRL recuperati vengono scritti solo qui).
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -config.
.PARAMETER MostraVociRevocate
    Se specificato, esegue anche "certutil -dump -v" sulla CRL per contare le
    singole voci revocate (solo conteggio, non l'elenco integrale nel record
    di evidenza) invece di leggere solo l'intestazione.
.EXAMPLE
    .\06-Revoca.ps1 -PercorsoUscita C:\Evidenze\CA01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PercorsoUscita,

    [ValidateSet('JSON', 'CSV')]
    [string]$Formato = 'JSON',

    [switch]$Verboso,

    [string]$ConfigCA = '',

    [switch]$MostraVociRevocate
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'Comune.ps1')

if ($Verboso) { $VerbosePreference = 'Continue' }

$nomeProgramma = '06-Revoca'
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

$argomentiConfig = @()
if (-not [string]::IsNullOrWhiteSpace($ConfigCA)) { $argomentiConfig = @('-config', $ConfigCA) }

function ConvertTo-VoceCDP {
    <#
    .SYNOPSIS
        Interpreta una singola voce di CRLPublicationURLs/CACertPublicationURLs
        nel formato "<flag numerico>:<percorso o URL>".
    #>
    param([string]$Voce)

    if ($Voce -notmatch '^(\d+):(.+)$') {
        return [PSCustomObject]@{ FlagGrezzo = $null; Percorso = $Voce; Tipo = 'sconosciuto'; PubblicaSuCDP = $null; PubblicaSuAIA = $null }
    }
    $flag = [int]$Matches[1]
    $percorso = $Matches[2]

    $tipo =
        if ($percorso -match '^https?://') { 'HTTP' }
        elseif ($percorso -match '^ldap://') { 'LDAP' }
        elseif ($percorso -match '^file://' -or $percorso -match '^[A-Za-z]:\\' -or $percorso -match '^\\\\') { 'FileLocale/UNC' }
        else { 'sconosciuto' }

    # Bit comunemente documentati nelle guide di configurazione ADCS per
    # CRLPublicationURLs/CACertPublicationURLs (interpretazione best-effort).
    [PSCustomObject]@{
        FlagGrezzo    = $flag
        Percorso      = $percorso
        Tipo          = $tipo
        PubblicazioneServer = [bool]($flag -band 0x1)
        AggiuntaCDPCertificato = [bool]($flag -band 0x2)
        AggiuntaFreshestCRL    = [bool]($flag -band 0x4)
        AggiuntaCRLDeltaCDP    = [bool]($flag -band 0x8)
    }
}

# --- 06.01: URL/percorsi CDP e AIA configurati ------------------------------
foreach ($voce in @(
        @{ Id = '06.01'; Chiave = 'CA\CRLPublicationURLs'; Descrizione = 'Punti di distribuzione CRL configurati (CDP)' },
        @{ Id = '06.02'; Chiave = 'CA\CACertPublicationURLs'; Descrizione = 'Punti di pubblicazione del certificato CA configurati (AIA)' }
    )) {
    $riepilogo.AccertamentiTentati++
    try {
        $risultato = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', $voce.Chiave) + $argomentiConfig)
        if ($risultato.CodiceUscita -ne 0 -or $risultato.Errore) {
            throw "certutil -getreg $($voce.Chiave) ha restituito codice $($risultato.CodiceUscita): $($risultato.Errore)"
        }
        $righeValore = $risultato.Output | Where-Object { $_ -match '^\s*\d+:' }
        $vociInterpretate = @($righeValore | ForEach-Object { ConvertTo-VoceCDP -Voce ($_.Trim()) })

        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo $voce.Id -Dominio 'Revoca' `
                    -Accertamento $voce.Descrizione -Valore $vociInterpretate -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiRiusciti++

        if ($voce.Id -eq '06.01') { $global:vociCDP = $vociInterpretate }
    }
    catch {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo $voce.Id -Dominio 'Revoca' `
                    -Accertamento $voce.Descrizione -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}

# --- 06.03: raggiungibilità di base degli endpoint HTTP/LDAP configurati ---
$riepilogo.AccertamentiTentati++
try {
    $risultatiRaggiungibilita = [System.Collections.Generic.List[object]]::new()
    foreach ($voce in @($global:vociCDP)) {
        if ($voce.Tipo -eq 'FileLocale/UNC') {
            $risultatiRaggiungibilita.Add([PSCustomObject]@{ Percorso = $voce.Percorso; Tipo = $voce.Tipo; Esito = 'non applicabile (pubblicazione su file locale/UNC, non richiede verifica di rete)' })
            continue
        }
        try {
            $uri = [uri]$voce.Percorso
            $porta = if ($uri.Scheme -eq 'https') { 443 } elseif ($uri.Scheme -eq 'ldap') { 389 } else { 80 }
            $esito = Test-NetConnection -ComputerName $uri.Host -Port $porta -InformationLevel Quiet -WarningAction SilentlyContinue
            $risultatiRaggiungibilita.Add([PSCustomObject]@{ Percorso = $voce.Percorso; Tipo = $voce.Tipo; Host = $uri.Host; Porta = $porta; Raggiungibile = [bool]$esito })
        }
        catch {
            $risultatiRaggiungibilita.Add([PSCustomObject]@{ Percorso = $voce.Percorso; Tipo = $voce.Tipo; Esito = "non verificabile: $($_.Exception.Message)" })
        }
    }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.03' -Dominio 'Revoca' `
                -Accertamento 'Raggiungibilità di rete di base (solo porta) degli endpoint CDP/AIA HTTP/LDAP configurati' `
                -Valore @($risultatiRaggiungibilita) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.03' -Dominio 'Revoca' `
                -Accertamento 'Raggiungibilità di rete di base degli endpoint CDP/AIA' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 06.04/06.05: recupero certificato CA e CRL corrente, metadati ----------
$percorsoCACertTemp = Join-Path -Path $PercorsoUscita -ChildPath 'temp_CACert_06Revoca.cer'
$percorsoCACrlTemp = Join-Path -Path $PercorsoUscita -ChildPath 'temp_CACRL_06Revoca.crl'

$riepilogo.AccertamentiTentati++
$recuperoCertOk = $false
try {
    $risultatoCert = Invoke-CertutilSolaLettura -Argomenti (@('-ca.cert', $percorsoCACertTemp) + $argomentiConfig)
    if ($risultatoCert.CodiceUscita -ne 0 -or -not (Test-Path -LiteralPath $percorsoCACertTemp)) {
        throw "certutil -ca.cert ha restituito codice $($risultatoCert.CodiceUscita): $($risultatoCert.Errore)"
    }
    $recuperoCertOk = $true
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.04' -Dominio 'Revoca' `
                -Accertamento 'Recupero del certificato corrente della CA (certutil -ca.cert)' `
                -Valore "Recuperato correttamente in $percorsoCACertTemp" -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.04' -Dominio 'Revoca' `
                -Accertamento 'Recupero del certificato corrente della CA (certutil -ca.cert)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

$riepilogo.AccertamentiTentati++
try {
    $risultatoCrl = Invoke-CertutilSolaLettura -Argomenti (@('-ca.crl', $percorsoCACrlTemp) + $argomentiConfig)
    if ($risultatoCrl.CodiceUscita -ne 0 -or -not (Test-Path -LiteralPath $percorsoCACrlTemp)) {
        throw "certutil -ca.crl ha restituito codice $($risultatoCrl.CodiceUscita): $($risultatoCrl.Errore)"
    }

    $argomentiDump = if ($MostraVociRevocate) { @('-dump', '-v', $percorsoCACrlTemp) } else { @('-dump', $percorsoCACrlTemp) }
    $risultatoDump = Invoke-CertutilSolaLettura -Argomenti $argomentiDump
    $testoDump = $risultatoDump.Output -join "`n"

    $thisUpdate = $null; $nextUpdate = $null; $numeroCrl = $null
    foreach ($riga in $risultatoDump.Output) {
        if (-not $thisUpdate -and $riga -match '(?i)(this update|thisupdate|effective date)\s*[:=]\s*(.+)$') { $thisUpdate = $Matches[2].Trim() }
        if (-not $nextUpdate -and $riga -match '(?i)(next update|nextupdate|next crl publish)\s*[:=]\s*(.+)$') { $nextUpdate = $Matches[2].Trim() }
        if (-not $numeroCrl -and $riga -match '(?i)(crl number)\s*[:=]\s*(.+)$') { $numeroCrl = $Matches[2].Trim() }
    }

    $freschezza = 'non verificabile: campo Next Update non riconosciuto nell output di certutil -dump'
    if ($nextUpdate) {
        try {
            $dataNextUpdate = [datetime]$nextUpdate
            $freschezza = if ($dataNextUpdate -lt (Get-Date)) { "SCADUTA da $((Get-Date) - $dataNextUpdate)" } else { "valida ancora per $($dataNextUpdate - (Get-Date))" }
        }
        catch { }
    }

    $conteggioVociRevocate = $null
    if ($MostraVociRevocate) {
        $conteggioVociRevocate = @($risultatoDump.Output | Select-String -Pattern '(?i)Serial Number|Numero di serie' -AllMatches).Count
    }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.05' -Dominio 'Revoca' `
                -Accertamento 'Metadati della CRL correntemente pubblicata (certutil -ca.crl + certutil -dump)' `
                -Valore ([PSCustomObject]@{
                    ThisUpdate            = $thisUpdate
                    NextUpdate            = $nextUpdate
                    NumeroCRL             = $numeroCrl
                    Freschezza            = $freschezza
                    ConteggioVociRevocate = $conteggioVociRevocate
                    Nota                  = 'ConteggioVociRevocate valorizzato solo con -MostraVociRevocate; per default vengono letti solo i metadati di intestazione, senza enumerare le voci.'
                    TestoIntegraleDump    = $testoDump
                }) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.05' -Dominio 'Revoca' `
                -Accertamento 'Metadati della CRL correntemente pubblicata' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 06.06: validazione catena/CDP/AIA/OCSP con certutil -verify -urlfetch --
$riepilogo.AccertamentiTentati++
if ($recuperoCertOk) {
    try {
        $risultatoVerify = Invoke-CertutilSolaLettura -Argomenti @('-verify', '-urlfetch', $percorsoCACertTemp)
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.06' -Dominio 'Revoca' `
                    -Accertamento 'Validazione catena/CDP/AIA/OCSP (certutil -verify -urlfetch)' `
                    -Valore ([PSCustomObject]@{ CodiceUscita = $risultatoVerify.CodiceUscita; Output = ($risultatoVerify.Output -join "`n") }) `
                    -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiRiusciti++
    }
    catch {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.06' -Dominio 'Revoca' `
                    -Accertamento 'Validazione catena/CDP/AIA/OCSP (certutil -verify -urlfetch)' `
                    -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}
else {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '06.06' -Dominio 'Revoca' `
                -Accertamento 'Validazione catena/CDP/AIA/OCSP (certutil -verify -urlfetch)' `
                -Valore 'Non eseguita: recupero del certificato CA non riuscito (vedi 06.04).' `
                -Stato 'non applicabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# Nota: il certificato CA e la CRL recuperati (temp_CACert_06Revoca.cer,
# temp_CACRL_06Revoca.crl) NON vengono eliminati al termine: il verbo Remove
# non e ammesso in questa raccolta a sola lettura, e in ogni caso questi file
# sono essi stessi evidenza legittima (dati pubblici gia pubblicati dalla CA),
# quindi restano intenzionalmente in -PercorsoUscita.

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_06_Revoca' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_06_Revoca' -Formato 'JSON' | Out-Null

Write-Host "Programma 06 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
