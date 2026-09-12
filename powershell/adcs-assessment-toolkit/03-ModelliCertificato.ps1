<#
.SYNOPSIS
    Modelli di certificato: elenco, versione schema, scopi di utilizzo (EKU),
    requisiti di approvazione, esportabilità della chiave privata, numero di
    firme RA richieste.
.DESCRIPTION
    Combina due fonti di sola lettura:
      1. certutil -Template e certutil -CATemplates (visione lato CA: cosa e
         effettivamente abilitato su questa CA).
      2. Gli oggetti modello in Active Directory (Get-ADObject sotto
         CN=Certificate Templates,CN=Public Key Services,CN=Services,
         CN=Configuration), per i dettagli non esposti da certutil -Template:
         msPKI-Enrollment-Flag, msPKI-Private-Key-Flag, msPKI-RA-Signature.

    Il modulo ActiveDirectory (RSAT), se presente, viene usato tramite il
    meccanismo di caricamento automatico dei moduli di PowerShell: questo
    programma non chiama mai Import-Module (verbo "Import" non ammesso in
    questa raccolta). Se il modulo non è installato o l'auto-caricamento è
    disabilitato, Get-ADObject fallira e l'accertamento verra marcato "non
    verificabile", senza bloccare il resto del programma.

    Solo tre flag a bit sono decodificati con la certezza sufficiente per
    essere dichiarati con nome (documentazione pubblica dello schema dei
    modelli di certificato):
      - msPKI-Private-Key-Flag  bit 0x00000010 = chiave privata esportabile
      - msPKI-Enrollment-Flag   bit 0x00000002 = richiede approvazione manager
      - msPKI-Enrollment-Flag   bit 0x00000020 = autoiscrizione abilitata
    Gli altri bit dei due flag vengono riportati solo come valore grezzo, non
    decodificato, per non rischiare di dichiarare un significato non certo.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: certutil.exe; modulo ActiveDirectory (RSAT) per i dettagli
    dei flag dei modelli (opzionale: senza di esso si ottengono comunque
    elenco e versione da certutil -Template/-CATemplates).
    Privilegi minimi necessari: diritto di lettura standard sui modelli in AD
    (Authenticated Users ha di norma diritto di lettura sul container
    Certificate Templates); nessun privilegio amministrativo.
    Controlli dell'assessment coperti: 03 (Modelli di certificato).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi fino a qualche decina di secondi
    con molte decine di modelli.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a certutil -config per gli
    accertamenti lato CA (-CATemplates). La lettura degli oggetti AD non
    dipende da questo parametro.
.EXAMPLE
    .\03-ModelliCertificato.ps1 -PercorsoUscita C:\Evidenze\CA01
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

$nomeProgramma = '03-ModelliCertificato'
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

# --- 03.01: modelli abilitati su questa CA (certutil -CATemplates) --------
$riepilogo.AccertamentiTentati++
try {
    $risultatoCATemplates = Invoke-CertutilSolaLettura -Argomenti (@('-CATemplates') + $argomentiConfig)
    if ($risultatoCATemplates.CodiceUscita -ne 0 -or $risultatoCATemplates.Errore) {
        throw "certutil -CATemplates ha restituito codice $($risultatoCATemplates.CodiceUscita): $($risultatoCATemplates.Errore)"
    }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.01' -Dominio 'ModelliCertificato' `
                -Accertamento 'Modelli di certificato abilitati su questa CA (certutil -CATemplates)' `
                -Valore ($risultatoCATemplates.Output -join "`n") -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.01' -Dominio 'ModelliCertificato' `
                -Accertamento 'Modelli di certificato abilitati su questa CA (certutil -CATemplates)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 03.02: elenco generale modelli noti (certutil -Template) --------------
$riepilogo.AccertamentiTentati++
try {
    $risultatoTemplate = Invoke-CertutilSolaLettura -Argomenti (@('-Template'))
    if ($risultatoTemplate.CodiceUscita -ne 0 -or $risultatoTemplate.Errore) {
        throw "certutil -Template ha restituito codice $($risultatoTemplate.CodiceUscita): $($risultatoTemplate.Errore)"
    }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.02' -Dominio 'ModelliCertificato' `
                -Accertamento 'Elenco generale dei modelli di certificato noti (certutil -Template)' `
                -Valore ($risultatoTemplate.Output -join "`n") -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.02' -Dominio 'ModelliCertificato' `
                -Accertamento 'Elenco generale dei modelli di certificato noti (certutil -Template)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 03.03+: dettagli per singolo modello da Active Directory --------------
$riepilogo.AccertamentiTentati++
try {
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    $containerModelli = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"

    $modelli = Get-ADObject -SearchBase $containerModelli -Filter { objectClass -eq 'pKICertificateTemplate' } `
        -Properties DisplayName, 'msPKI-Template-Schema-Version', 'msPKI-Enrollment-Flag', 'msPKI-Private-Key-Flag', `
                    'msPKI-RA-Signature', pKIExtendedKeyUsage, 'msPKI-Certificate-Application-Policy', revision `
        -ErrorAction Stop

    $riepilogo.AccertamentiRiusciti++

    foreach ($modello in $modelli) {
        $riepilogo.AccertamentiTentati++
        try {
            $flagEnrollment = [uint32]($modello.'msPKI-Enrollment-Flag')
            $flagPrivateKey = [uint32]($modello.'msPKI-Private-Key-Flag')

            $esportabile = [bool]($flagPrivateKey -band 0x00000010)
            $richiedeApprovazioneManager = [bool]($flagEnrollment -band 0x00000002)
            $autoiscrizioneAbilitata = [bool]($flagEnrollment -band 0x00000020)

            $dettaglio = [PSCustomObject]@{
                Nome                        = $modello.Name
                DisplayName                 = $modello.DisplayName
                VersioneSchema              = $modello.'msPKI-Template-Schema-Version'
                Revisione                   = $modello.revision
                ChiavePrivataEsportabile    = $esportabile
                RichiedeApprovazioneManager = $richiedeApprovazioneManager
                AutoiscrizioneAbilitata     = $autoiscrizioneAbilitata
                NumeroFirmeRARichieste      = $modello.'msPKI-RA-Signature'
                ScopiUtilizzoEKU            = @($modello.pKIExtendedKeyUsage)
                PolicyApplicazione          = @($modello.'msPKI-Certificate-Application-Policy')
                FlagEnrollmentGrezzo        = ('0x{0:X8}' -f $flagEnrollment)
                FlagPrivateKeyGrezzo        = ('0x{0:X8}' -f $flagPrivateKey)
                DistinguishedName           = $modello.DistinguishedName
            }

            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.03' -Dominio 'ModelliCertificato' `
                        -Accertamento "Dettaglio modello: $($modello.Name)" `
                        -Valore $dettaglio -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiRiusciti++
        }
        catch {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.03' -Dominio 'ModelliCertificato' `
                        -Accertamento "Dettaglio modello: $($modello.Name)" `
                        -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiFalliti++
        }
    }
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '03.03' -Dominio 'ModelliCertificato' `
                -Accertamento 'Dettaglio modelli da Active Directory (flag di iscrizione/chiave privata/firme RA)' `
                -Valore "Modulo ActiveDirectory non disponibile o interrogazione fallita: $($_.Exception.Message). Elenco/versione restano disponibili da certutil -Template/-CATemplates sopra." `
                -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_03_ModelliCertificato' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_03_ModelliCertificato' -Formato 'JSON' | Out-Null

Write-Host "Programma 03 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
