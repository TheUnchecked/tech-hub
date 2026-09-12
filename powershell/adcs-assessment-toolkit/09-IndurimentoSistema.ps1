<#
.SYNOPSIS
    Indurimento del sistema: servizi attivi, porte in ascolto, aggiornamenti
    installati, protocolli TLS e cifrari abilitati/disabilitati, appartenenza
    a dominio dell'host della CA.
.DESCRIPTION
    Ogni accertamento usa esclusivamente cmdlet di lettura nativi
    (Get-CimInstance, Get-NetTCPConnection, Get-HotFix, Get-ItemProperty/
    Get-ChildItem sul registro SCHANNEL, nessun binario esterno).

    Per i protocolli/cifrari TLS: l'assenza di una sottochiave per un dato
    protocollo/cifrario sotto SCHANNEL significa che quel protocollo/cifrario
    segue il comportamento predefinito del sistema operativo (non
    esplicitamente configurato), non che sia disabilitato: questa distinzione
    e riportata esplicitamente nel record, per non dichiarare una conclusione
    di conformita che spetta alla fase di valutazione a valle.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: nessuno oltre a PowerShell 5.1+/7.x; il modulo NetTCPIP
    (incluso di serie in Windows Server 2016+) per Get-NetTCPConnection.
    Privilegi minimi necessari: nessun privilegio amministrativo per la
    maggior parte degli accertamenti; la lettura di alcune chiavi SCHANNEL
    puo richiedere permessi di lettura standard sul registro (concessi di
    norma a tutti gli utenti autenticati).
    Controlli dell'assessment coperti: 09 (Indurimento del sistema). Questo
    programma va eseguito localmente sull host della CA (non supporta
    -ConfigCA: gli accertamenti riguardano il sistema operativo host, non la
    CA come servizio applicativo).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi fino a circa un minuto (Get-HotFix
    puo richiedere qualche secondo in piu su host con molti aggiornamenti).
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.EXAMPLE
    .\09-IndurimentoSistema.ps1 -PercorsoUscita C:\Evidenze\CA01
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

$nomeProgramma = '09-IndurimentoSistema'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# --- 09.01: servizi attivi ---------------------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $serviziAttivi = Get-CimInstance -ClassName Win32_Service -Filter "State='Running'" -ErrorAction Stop |
        Select-Object Name, DisplayName, StartMode, StartName
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.01' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Servizi Windows attualmente in esecuzione' `
                -Valore @($serviziAttivi) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.01' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Servizi Windows attualmente in esecuzione' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 09.02: porte TCP in ascolto --------------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $portInAscolto = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort -Unique
    # Si costruisce un nuovo oggetto per ciascuna porta (invece di usare
    # Add-Member, verbo "Add" non ammesso in questa raccolta a sola lettura).
    $portInAscoltoConProcesso = foreach ($p in $portInAscolto) {
        $nomeProcesso = 'sconosciuto'
        try {
            $processo = Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue
            if ($processo) { $nomeProcesso = $processo.ProcessName }
        }
        catch { }
        [PSCustomObject]@{
            LocalAddress   = $p.LocalAddress
            LocalPort      = $p.LocalPort
            OwningProcess  = $p.OwningProcess
            NomeProcesso   = $nomeProcesso
        }
    }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.02' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Porte TCP in ascolto' -Valore @($portInAscoltoConProcesso) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.02' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Porte TCP in ascolto' -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 09.03: aggiornamenti installati ----------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $hotfix = Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledOn |
        Sort-Object InstalledOn -Descending
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.03' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Aggiornamenti installati (Get-HotFix: elenco non necessariamente completo per tutti i tipi di pacchetto di aggiornamento, limite noto del cmdlet)' `
                -Valore @($hotfix) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.03' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Aggiornamenti installati (Get-HotFix)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 09.04: protocolli e cifrari TLS/SCHANNEL -------------------------------
$riepilogo.AccertamentiTentati++
try {
    $baseSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    $risultatiSchannel = [System.Collections.Generic.List[object]]::new()

    foreach ($categoria in 'Protocols', 'Ciphers', 'Hashes', 'KeyExchangeAlgorithms') {
        $percorsoCategoria = Join-Path $baseSchannel $categoria
        if (-not (Test-Path -LiteralPath $percorsoCategoria)) {
            $risultatiSchannel.Add([PSCustomObject]@{ Categoria = $categoria; Nota = 'Nessuna sottochiave presente: nessun elemento di questa categoria configurato esplicitamente (segue i predefiniti del sistema operativo).' })
            continue
        }
        foreach ($sottochiave in Get-ChildItem -Path $percorsoCategoria -ErrorAction SilentlyContinue) {
            $nomeElemento = $sottochiave.PSChildName
            $percorsoElemento = $sottochiave.PSPath
            $enabled = $null; $disabledByDefault = $null
            try {
                $valori = Get-ItemProperty -Path $percorsoElemento -ErrorAction Stop
                if ($null -ne $valori.PSObject.Properties['Enabled']) { $enabled = $valori.Enabled }
                if ($null -ne $valori.PSObject.Properties['DisabledByDefault']) { $disabledByDefault = $valori.DisabledByDefault }
            }
            catch { }

            $sottochiaviClientServer = Get-ChildItem -Path $percorsoElemento -ErrorAction SilentlyContinue
            if ($sottochiaviClientServer) {
                foreach ($cs in $sottochiaviClientServer) {
                    $valoriCS = Get-ItemProperty -Path $cs.PSPath -ErrorAction SilentlyContinue
                    $risultatiSchannel.Add([PSCustomObject]@{
                            Categoria         = $categoria
                            Elemento          = "$nomeElemento\$($cs.PSChildName)"
                            Enabled           = if ($valoriCS -and $valoriCS.PSObject.Properties['Enabled']) { $valoriCS.Enabled } else { $null }
                            DisabledByDefault = if ($valoriCS -and $valoriCS.PSObject.Properties['DisabledByDefault']) { $valoriCS.DisabledByDefault } else { $null }
                            Nota              = 'Nessun valore esplicito trovato = segue il comportamento predefinito del sistema operativo per questa versione, non necessariamente disabilitato.'
                        })
                }
            }
            else {
                $risultatiSchannel.Add([PSCustomObject]@{
                        Categoria         = $categoria
                        Elemento          = $nomeElemento
                        Enabled           = $enabled
                        DisabledByDefault = $disabledByDefault
                        Nota              = 'Nessun valore esplicito trovato = segue il comportamento predefinito del sistema operativo per questa versione, non necessariamente disabilitato.'
                    })
            }
        }
    }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.04' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Protocolli/cifrari/hash/algoritmi di scambio chiave TLS configurati esplicitamente in SCHANNEL' `
                -Valore @($risultatiSchannel) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.04' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Protocolli/cifrari TLS SCHANNEL' -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 09.05: appartenenza a dominio ------------------------------------------
$riepilogo.AccertamentiTentati++
try {
    $sistema = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop |
        Select-Object Name, Domain, PartOfDomain, DomainRole
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.05' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Appartenenza a dominio dell host della CA' -Valore $sistema -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '09.05' -Dominio 'IndurimentoSistema' `
                -Accertamento 'Appartenenza a dominio dell host della CA' -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_09_IndurimentoSistema' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_09_IndurimentoSistema' -Formato 'JSON' | Out-Null

Write-Host "Programma 09 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
