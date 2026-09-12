<#
.SYNOPSIS
    Inventario della CA ADCS: identità, tipo, catena di certificazione,
    algoritmo di firma, lunghezza chiave, validità, provider crittografico e
    indicazione di presenza HSM.
.DESCRIPTION
    Legge esclusivamente informazioni già esposte dalla CA (certutil -CAInfo,
    certutil -key), dal registro (nome CA attiva) e dagli store certificati
    locali di sola lettura (Cert:\LocalMachine\My). La costruzione della catena
    di certificazione avviene con X509Chain in modalità NoCheck (nessuna
    verifica di revoca online): questo programma si occupa di inventario, non
    di revoca (vedi programma 06 per CRL/OCSP), quindi non effettua alcuna
    chiamata di rete.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe disponibile; accesso in lettura allo store
    certificati locale (Cert:\LocalMachine\My) e al registro di configurazione
    CertSvc; se la CA è remota, indicare -ConfigCA "Server\NomeCA" (in tal
    caso la lettura dello store locale e della catena viene saltata e marcata
    "non applicabile", perché richiederebbe accesso al filesystem/registro del
    server remoto che questo programma non tenta).
    Privilegi minimi necessari: nessun privilegio amministrativo; diritto di
    lettura standard sull'host della CA.
    Controlli dell'assessment coperti: 01 (Inventario CA).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi, indipendente dalla dimensione
    della CA (non interroga il database di emissione).
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -config. Se omesso, si
    usa la CA di default locale e si tenta anche la lettura locale di
    store/registro.
.EXAMPLE
    .\01-InventarioCA.ps1 -PercorsoUscita C:\Evidenze\CA01
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

$nomeProgramma = '01-InventarioCA'
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
$caLocale = [string]::IsNullOrWhiteSpace($ConfigCA)
if (-not $caLocale) {
    $argomentiConfig = @('-config', $ConfigCA)
}

# --- 01.01: nome e tipo CA (certutil -CAInfo) -------------------------------
$riepilogo.AccertamentiTentati++
try {
    $risultatoCAInfo = Invoke-CertutilSolaLettura -Argomenti (@('-CAInfo') + $argomentiConfig)
    if ($risultatoCAInfo.CodiceUscita -ne 0 -or $risultatoCAInfo.Errore) {
        throw "certutil -CAInfo ha restituito codice $($risultatoCAInfo.CodiceUscita): $($risultatoCAInfo.Errore)"
    }
    $testoCAInfo = $risultatoCAInfo.Output -join "`n"

    $rigaTipo = $risultatoCAInfo.Output | Where-Object { $_ -match 'CA type|Tipo CA' } | Select-Object -First 1
    $tipoCA = if ($rigaTipo) { $rigaTipo.Trim() } else { 'non individuato nel testo restituito da certutil -CAInfo' }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.01' -Dominio 'InventarioCA' `
                -Accertamento 'Tipo di CA (radice o subordinata) da certutil -CAInfo' `
                -Valore $tipoCA -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.01b' -Dominio 'InventarioCA' `
                -Accertamento 'Uscita integrale di certutil -CAInfo (riferimento)' `
                -Valore $testoCAInfo -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti += 2
    $riepilogo.AccertamentiTentati++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.01' -Dominio 'InventarioCA' `
                -Accertamento 'Tipo di CA (radice o subordinata) da certutil -CAInfo' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 01.02: nome CA attiva dal registro (solo lettura via certutil -getreg) -
$riepilogo.AccertamentiTentati++
$nomeCAAttiva = $null
try {
    $risultatoNome = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', 'CA\CommonName') + $argomentiConfig)
    $nomeCAAttiva = ($risultatoNome.Output | Where-Object { $_ -match '=' } | Select-Object -First 1)
    if (-not $nomeCAAttiva) { $nomeCAAttiva = ($risultatoNome.Output -join ' | ') }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.02' -Dominio 'InventarioCA' `
                -Accertamento 'Nome comune (CommonName) della CA' `
                -Valore $nomeCAAttiva -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.02' -Dominio 'InventarioCA' `
                -Accertamento 'Nome comune (CommonName) della CA' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 01.03: presenza HSM / provider crittografico (certutil -key) ----------
$riepilogo.AccertamentiTentati++
try {
    $risultatoKey = Invoke-CertutilSolaLettura -Argomenti (@('-key'))
    if ($risultatoKey.CodiceUscita -ne 0 -or $risultatoKey.Errore) {
        throw "certutil -key ha restituito codice $($risultatoKey.CodiceUscita): $($risultatoKey.Errore)"
    }
    $testoKey = $risultatoKey.Output -join "`n"
    $indicatoriHSM = @('nCipher', 'nShield', 'Luna', 'SafeNet', 'Utimaco', 'Thales', 'CryptoServer', 'YubiHSM', 'Entrust nShield')
    $hsmRilevato = $false
    foreach ($ind in $indicatoriHSM) {
        if ($testoKey -match [regex]::Escape($ind)) { $hsmRilevato = $true; break }
    }
    $righeProvider = $risultatoKey.Output | Where-Object { $_ -match 'Provider' }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.03' -Dominio 'InventarioCA' `
                -Accertamento 'Provider crittografico (CSP/KSP) e indicazione di presenza HSM (certutil -key)' `
                -Valore ([PSCustomObject]@{
                    IndicazioneHSM      = $hsmRilevato
                    RigheProviderTrovate = @($righeProvider)
                    Nota                = 'Indicazione basata su corrispondenza testuale con nomi noti di fornitori HSM nell elenco container chiave; non sostituisce una verifica fisica/di configurazione.'
                }) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.03' -Dominio 'InventarioCA' `
                -Accertamento 'Provider crittografico (CSP/KSP) e indicazione di presenza HSM (certutil -key)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 01.04, 01.05, 01.06: certificato CA locale, catena, algoritmo/lunghezza,
#     validita (solo se la CA e locale: richiede accesso allo store locale) --
if ($caLocale) {
    $riepilogo.AccertamentiTentati++
    try {
        $hashCACert = $null
        try {
            $percorsoConfigReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction Stop
            $nomeConfigAttiva = $percorsoConfigReg.Active
            if ($nomeConfigAttiva) {
                $chiaveCA = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$nomeConfigAttiva" -ErrorAction Stop
                $hashCACert = $chiaveCA.CACertHash
            }
        }
        catch {
            Write-Verbose "Lettura registro CACertHash non riuscita: $($_.Exception.Message)"
        }

        $certificatiMy = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop
        $certCA = $null
        if ($hashCACert) {
            $hashNormalizzato = ($hashCACert -join '').Replace(' ', '').ToUpperInvariant()
            $certCA = $certificatiMy | Where-Object { $_.Thumbprint -eq $hashNormalizzato } | Select-Object -First 1
        }
        if (-not $certCA) {
            # Ripiego: nessun certificato identificato con certezza tramite l'hash di registro.
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.04' -Dominio 'InventarioCA' `
                        -Accertamento 'Identificazione del certificato della CA nello store locale (Cert:\LocalMachine\My)' `
                        -Valore 'Impossibile identificare con certezza il certificato della CA tramite CACertHash del registro; verificare manualmente quale certificato in Cert:\LocalMachine\My corrisponde alla CA.' `
                        -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiFalliti++
        }
        else {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.04' -Dominio 'InventarioCA' `
                        -Accertamento 'Algoritmo di firma e lunghezza chiave del certificato CA' `
                        -Valore ([PSCustomObject]@{
                            Soggetto           = $certCA.Subject
                            AlgoritmoFirma     = $certCA.SignatureAlgorithm.FriendlyName
                            LunghezzaChiave    = $certCA.PublicKey.Key.KeySize
                            Thumbprint         = $certCA.Thumbprint
                        }) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))

            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.05' -Dominio 'InventarioCA' `
                        -Accertamento 'Periodo di validita del certificato CA' `
                        -Valore ([PSCustomObject]@{ NotBefore = $certCA.NotBefore; NotAfter = $certCA.NotAfter }) `
                        -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))

            try {
                $catena = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $catena.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $catena.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
                $costruzioneRiuscita = $catena.Build($certCA)
                $elementiCatena = $catena.ChainElements | ForEach-Object {
                    [PSCustomObject]@{ Soggetto = $_.Certificate.Subject; Emittente = $_.Certificate.Issuer; Thumbprint = $_.Certificate.Thumbprint }
                }

                $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.06' -Dominio 'InventarioCA' `
                            -Accertamento 'Catena di certificazione (costruita localmente, nessuna verifica di revoca online)' `
                            -Valore ([PSCustomObject]@{ CostruzioneCompleta = $costruzioneRiuscita; Elementi = @($elementiCatena) }) `
                            -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
                $riepilogo.AccertamentiRiusciti += 3
            }
            catch {
                $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.06' -Dominio 'InventarioCA' `
                            -Accertamento 'Catena di certificazione (costruita localmente, nessuna verifica di revoca online)' `
                            -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
                $riepilogo.AccertamentiRiusciti += 2
                $riepilogo.AccertamentiFalliti++
            }
        }
    }
    catch {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.04' -Dominio 'InventarioCA' `
                    -Accertamento 'Lettura dello store certificati locale (Cert:\LocalMachine\My)' `
                    -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}
else {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '01.04' -Dominio 'InventarioCA' `
                -Accertamento 'Certificato CA, catena, algoritmo/lunghezza chiave, validita (richiede store locale)' `
                -Valore "CA remota (-ConfigCA '$ConfigCA'): lettura dello store locale non tentata, eseguire questo programma direttamente sull host della CA per questi accertamenti." `
                -Stato 'non applicabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_01_InventarioCA' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_01_InventarioCA' -Formato 'JSON' | Out-Null

Write-Host "Programma 01 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
