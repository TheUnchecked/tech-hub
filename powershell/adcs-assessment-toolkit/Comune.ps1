<#
.SYNOPSIS
    Funzioni condivise per la raccolta evidenze di conformità ADCS — sola lettura.
.DESCRIPTION
    Modulo dot-sourced da tutti i programmi della raccolta. Non contiene alcuna
    funzione che modifichi lo stato del sistema esaminato: costruisce oggetti in
    memoria, legge file/registro/CA, e scrive esclusivamente nella cartella di
    uscita indicata dal chiamante.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Nessun controllo di assessment è coperto direttamente da questo file: è
    infrastruttura comune richiamata dagli altri programmi (00-10).
#>

Set-StrictMode -Version Latest

function Format-RecordEvidenza {
    <#
    .SYNOPSIS
        Costruisce un record di evidenza normalizzato secondo lo schema comune
        della raccolta (nessuna scrittura: solo costruzione di un oggetto in memoria).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$IdControllo,
        [Parameter(Mandatory = $true)][string]$Dominio,
        [Parameter(Mandatory = $true)][string]$Accertamento,
        [Parameter(Mandatory = $true)]$Valore,
        [Parameter(Mandatory = $true)]
        [ValidateSet('rilevato', 'non applicabile', 'non verificabile')]
        [string]$Stato,
        [Parameter(Mandatory = $true)]
        [ValidateSet('completo', 'campionario')]
        [string]$Completezza,
        [Parameter(Mandatory = $true)][string]$StrategiaLettura
    )

    [PSCustomObject]@{
        IdControllo      = $IdControllo
        Dominio          = $Dominio
        Accertamento     = $Accertamento
        Valore           = $Valore
        Stato            = $Stato
        DataOra          = (Get-Date).ToString('o')
        NomeHost         = $env:COMPUTERNAME
        Completezza      = $Completezza
        StrategiaLettura = $StrategiaLettura
    }
}

function Test-CartellaUscita {
    <#
    .SYNOPSIS
        Verifica che la cartella di uscita esista già. Non la crea mai:
        la creazione richiederebbe un cmdlet con verbo New/Set, non ammesso
        in questa raccolta a sola lettura.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PercorsoUscita)

    if (-not (Test-Path -LiteralPath $PercorsoUscita -PathType Container)) {
        throw "La cartella di uscita '$PercorsoUscita' non esiste. Crearla manualmente prima di eseguire il programma (questo strumento non crea cartelle, per restare in sola lettura)."
    }
    return $true
}

function Export-Evidenza {
    <#
    .SYNOPSIS
        Scrive un insieme di record (o un oggetto qualsiasi) nella cartella di
        uscita, in JSON o CSV. Scrive esclusivamente dentro -PercorsoUscita.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Dati,
        [Parameter(Mandatory = $true)][string]$PercorsoUscita,
        [Parameter(Mandatory = $true)][string]$NomeFileSenzaEstensione,
        [Parameter(Mandatory = $true)][ValidateSet('JSON', 'CSV')][string]$Formato,
        [switch]$Parziale
    )

    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null

    $suffisso = if ($Parziale) { '.PARZIALE' } else { '' }
    $estensione = if ($Formato -eq 'JSON') { 'json' } else { 'csv' }
    $percorsoFile = Join-Path -Path $PercorsoUscita -ChildPath "$NomeFileSenzaEstensione$suffisso.$estensione"

    if ($Formato -eq 'JSON') {
        $Dati | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $percorsoFile -Encoding utf8
    }
    else {
        $Dati | Export-Csv -LiteralPath $percorsoFile -NoTypeInformation -Encoding utf8
    }

    Write-Verbose "Scritto: $percorsoFile"
    return $percorsoFile
}

function Get-CertutilDisponibile {
    <#
    .SYNOPSIS
        Verifica la presenza di certutil.exe e ne restituisce il percorso e la versione file.
    #>
    [CmdletBinding()]
    param()

    $comando = Get-Command -Name 'certutil.exe' -ErrorAction SilentlyContinue
    if (-not $comando) {
        return [PSCustomObject]@{ Disponibile = $false; Percorso = $null; Versione = $null }
    }

    $versione = $null
    try {
        $versione = (Get-Item -LiteralPath $comando.Source -ErrorAction Stop).VersionInfo.FileVersion
    }
    catch {
        $versione = 'sconosciuta'
    }

    [PSCustomObject]@{ Disponibile = $true; Percorso = $comando.Source; Versione = $versione }
}

function Invoke-CertutilSolaLettura {
    <#
    .SYNOPSIS
        Esegue certutil.exe con un elenco di argomenti già filtrati come di sola
        lettura, catturando stdout/stderr, codice di uscita e tempo impiegato.
    .DESCRIPTION
        Gli argomenti sono passati come array a un processo esterno (nessun
        Invoke-Expression, nessuna interpretazione dinamica di stringhe), e ogni
        parametro di scrittura noto viene bloccato prima dell'esecuzione come
        controllo difensivo aggiuntivo, anche se il chiamante dovrebbe già
        passare solo argomenti di sola lettura.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Argomenti
    )

    $argomentiVietati = @('-setreg', '-delreg', '-installcert', '-revoke', '-resubmit',
        '-deleterow', '-repairstore', '-importpfx', '-renewcert', '-setcatemplates',
        '-backup', '-restore')
    foreach ($arg in $Argomenti) {
        foreach ($vietato in $argomentiVietati) {
            if ($arg -ieq $vietato) {
                throw "Argomento certutil non ammesso in questa raccolta (sola lettura): $arg"
            }
        }
    }

    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()
    $output = $null
    $codiceUscita = $null
    $errore = $null
    try {
        $output = & certutil.exe @Argomenti 2>&1
        $codiceUscita = $LASTEXITCODE
    }
    catch {
        $codiceUscita = -1
        $errore = $_.Exception.Message
    }
    $cronometro.Stop()

    [PSCustomObject]@{
        Argomenti    = $Argomenti -join ' '
        Output       = $output
        CodiceUscita = $codiceUscita
        Errore       = $errore
        DurataMs     = $cronometro.Elapsed.TotalMilliseconds
    }
}

function Get-StrategiaLettura {
    <#
    .SYNOPSIS
        Legge StrategiaPaginazione.json prodotto dal programma 00. Se assente o
        illeggibile, avvisa e segnala al chiamante di eseguire una prova rapida
        in linea e di registrarne l'esito nell'uscita (nessuna strategia cablata).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PercorsoUscita)

    $percorsoFile = Join-Path -Path $PercorsoUscita -ChildPath 'StrategiaPaginazione.json'

    if (Test-Path -LiteralPath $percorsoFile -PathType Leaf) {
        try {
            $strategia = Get-Content -LiteralPath $percorsoFile -Raw | ConvertFrom-Json
            return [PSCustomObject]@{
                Trovata               = $true
                StrategiaRaccomandata = $strategia.StrategiaRaccomandata
                FormatoDataAccettato  = $strategia.FormatoDataAccettato
                Dettaglio             = $strategia
            }
        }
        catch {
            Write-Warning "StrategiaPaginazione.json presente ma non leggibile: $($_.Exception.Message). Si procede con ripiego empirico."
        }
    }
    else {
        Write-Warning "StrategiaPaginazione.json non trovato in '$PercorsoUscita'. Eseguire prima 00-VerificaStrategiaPaginazione.ps1. Si procede con una prova rapida in linea come ripiego."
    }

    return [PSCustomObject]@{
        Trovata               = $false
        StrategiaRaccomandata = $null
        FormatoDataAccettato  = $null
        Dettaglio             = $null
    }
}

function Format-RiepilogoEsecuzione {
    <#
    .SYNOPSIS
        Costruisce l'oggetto di riepilogo esecuzione (in memoria) per un programma.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$NomeProgramma)

    [PSCustomObject]@{
        NomeProgramma        = $NomeProgramma
        NomeHost             = $env:COMPUTERNAME
        InizioEsecuzione     = (Get-Date).ToString('o')
        FineEsecuzione       = $null
        AccertamentiTentati  = 0
        AccertamentiRiusciti = 0
        AccertamentiFalliti  = 0
        RecordProdotti       = 0
        Note                 = [System.Collections.Generic.List[string]]::new()
    }
}

function Complete-RiepilogoEsecuzione {
    <#
    .SYNOPSIS
        Marca la fine dell'esecuzione nel riepilogo, prima dell'esportazione.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Riepilogo)

    $Riepilogo.FineEsecuzione = (Get-Date).ToString('o')
    return $Riepilogo
}
