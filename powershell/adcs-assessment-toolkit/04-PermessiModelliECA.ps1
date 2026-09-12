<#
.SYNOPSIS
    Permessi sui modelli di certificato e sulla CA: chi può iscrivere, chi può
    autoiscrivere, chi è gestore della CA, in forma leggibile.
.DESCRIPTION
    Per i modelli: legge nTSecurityDescriptor di ciascun oggetto modello in AD
    (Get-ADObject) ed enumera le ACE, evidenziando i diritti estesi Enroll
    (0e10c968-78fb-11d2-90d4-00c04f79dc55) e Autoenroll
    (a05b8cc2-17bc-4802-a710-e7c15ab866a2).

    Per la CA: non esiste un valore di registro leggibile con certutil -getreg
    per il descrittore di sicurezza della CA. L'unico metodo di sola lettura
    noto è ICertAdmin2::GetCASecurity, esposto tramite l'oggetto COM
    "CertificateAuthority.Admin" (controparte del metodo di scrittura
    SetCASecurity, mai invocato qui). A differenza dell'interfaccia di
    interrogazione del database (CertificateAuthority.View, deliberatamente
    non usata altrove in questa raccolta per incertezza sulle costanti
    numeriche interne di SetRestriction), GetCASecurity prende in ingresso una
    sola stringa (nome CA, vuoto per la CA locale) e restituisce il
    descrittore di sicurezza: non ci sono parametri numerici ambigui da
    indovinare, quindi il rischio di comportamento non verificato è molto
    piu basso. In caso di qualunque errore l'accertamento è comunque marcato
    "non verificabile" invece di bloccare il programma.

    I bit dell'AccessMask per i diritti "Manage CA" (0x1) e "Issue and Manage
    Certificates" (0x2) sul descrittore di sicurezza della CA sono decodificati
    secondo i valori comunemente documentati per ADCS; l'AccessMask grezzo
    viene comunque riportato accanto per riscontro manuale.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: modulo ActiveDirectory (RSAT) per gli ACL dei modelli;
    diritto di lettura standard su AD; per l'ACL della CA, diritto di lettura
    sulla CA (di norma sufficiente Authenticated Users).
    Privilegi minimi necessari: nessun privilegio amministrativo.
    Controlli dell'assessment coperti: 04 (Permessi su modelli e CA).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: da pochi secondi a circa un minuto in presenza
    di molte decine di modelli con ACL estese.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" passata a GetCASecurity. Se omesso, si usa la
    CA di default locale.
.EXAMPLE
    .\04-PermessiModelliECA.ps1 -PercorsoUscita C:\Evidenze\CA01
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

$nomeProgramma = '04-PermessiModelliECA'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

$GuidEnroll = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$GuidAutoenroll = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# --- 04.01: ACL dei modelli di certificato ---------------------------------
$riepilogo.AccertamentiTentati++
try {
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    $containerModelli = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
    $modelli = Get-ADObject -SearchBase $containerModelli -Filter { objectClass -eq 'pKICertificateTemplate' } `
        -Properties nTSecurityDescriptor -ErrorAction Stop
    $riepilogo.AccertamentiRiusciti++

    foreach ($modello in $modelli) {
        $riepilogo.AccertamentiTentati++
        try {
            $sd = $modello.nTSecurityDescriptor
            $vociEnroll = [System.Collections.Generic.List[object]]::new()
            $vociAutoenroll = [System.Collections.Generic.List[object]]::new()
            $tutteLeVoci = [System.Collections.Generic.List[object]]::new()

            foreach ($ace in $sd.Access) {
                $identita = $ace.IdentityReference.Value
                $tutteLeVoci.Add([PSCustomObject]@{
                        Identita        = $identita
                        TipoAccesso     = $ace.AccessControlType.ToString()
                        DirittiADRights = $ace.ActiveDirectoryRights.ToString()
                        ObjectType      = $ace.ObjectType
                    })

                if ($ace.ObjectType -eq $GuidEnroll -and $ace.AccessControlType -eq 'Allow') {
                    $vociEnroll.Add($identita)
                }
                if ($ace.ObjectType -eq $GuidAutoenroll -and $ace.AccessControlType -eq 'Allow') {
                    $vociAutoenroll.Add($identita)
                }
            }

            $dettaglio = [PSCustomObject]@{
                Modello            = $modello.Name
                DistinguishedName  = $modello.DistinguishedName
                PuoIscrivere       = @($vociEnroll | Sort-Object -Unique)
                PuoAutoiscrivere   = @($vociAutoenroll | Sort-Object -Unique)
                TutteLeVociACL     = @($tutteLeVoci)
            }

            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '04.01' -Dominio 'PermessiModelli' `
                        -Accertamento "ACL del modello: $($modello.Name)" `
                        -Valore $dettaglio -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiRiusciti++
        }
        catch {
            $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '04.01' -Dominio 'PermessiModelli' `
                        -Accertamento "ACL del modello: $($modello.Name)" `
                        -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
            $riepilogo.AccertamentiFalliti++
        }
    }
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '04.01' -Dominio 'PermessiModelli' `
                -Accertamento 'ACL dei modelli di certificato' `
                -Valore "Modulo ActiveDirectory non disponibile o interrogazione fallita: $($_.Exception.Message)" `
                -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 04.02: descrittore di sicurezza della CA (GetCASecurity, sola lettura) -
$riepilogo.AccertamentiTentati++
try {
    # Istanziazione COM tramite Activator/Type invece di New-Object: il verbo
    # "New" non e ammesso in questa raccolta a sola lettura, anche se qui
    # riguarda solo un oggetto in memoria del processo corrente.
    $tipoAdminCA = [Type]::GetTypeFromProgID('CertificateAuthority.Admin')
    $adminCA = [Activator]::CreateInstance($tipoAdminCA)
    $sdBase64 = $adminCA.GetCASecurity($ConfigCA)

    $bytesSD = [Convert]::FromBase64String($sdBase64)
    $rawSD = [System.Security.AccessControl.RawSecurityDescriptor]::new($bytesSD, 0)

    $DirittoManageCA = 0x1
    $DirittoIssueManageCertificati = 0x2

    $vociACL = [System.Collections.Generic.List[object]]::new()
    $gestoriCA = [System.Collections.Generic.List[string]]::new()
    $gestoriCertificati = [System.Collections.Generic.List[string]]::new()

    foreach ($ace in $rawSD.DiscretionaryAcl) {
        $identita = $null
        try { $identita = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value }
        catch { $identita = $ace.SecurityIdentifier.Value }

        $maschera = $ace.AccessMask
        $vociACL.Add([PSCustomObject]@{
                Identita       = $identita
                AccessMaskEsadecimale = ('0x{0:X}' -f $maschera)
                TipoACE        = $ace.AceType.ToString()
                ManageCA       = [bool]($maschera -band $DirittoManageCA)
                IssueManageCertificati = [bool]($maschera -band $DirittoIssueManageCertificati)
            })

        if (($maschera -band $DirittoManageCA) -and $ace.AceQualifier -eq 'AccessAllowed') { $gestoriCA.Add($identita) }
        if (($maschera -band $DirittoIssueManageCertificati) -and $ace.AceQualifier -eq 'AccessAllowed') { $gestoriCertificati.Add($identita) }
    }

    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '04.02' -Dominio 'PermessiCA' `
                -Accertamento 'Descrittore di sicurezza della CA (chi gestisce la CA / chi gestisce i certificati)' `
                -Valore ([PSCustomObject]@{
                    GestoriCA           = @($gestoriCA | Sort-Object -Unique)
                    GestoriCertificati  = @($gestoriCertificati | Sort-Object -Unique)
                    TutteLeVociACL      = @($vociACL)
                    Nota                = 'Bit ManageCA (0x1) e IssueManageCertificati (0x2) decodificati secondo i valori comunemente documentati per il descrittore di sicurezza CA ADCS; AccessMask grezzo riportato per riscontro.'
                }) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '04.02' -Dominio 'PermessiCA' `
                -Accertamento 'Descrittore di sicurezza della CA (GetCASecurity)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}
finally {
    if ($adminCA) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($adminCA) }
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_04_PermessiModelliECA' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_04_PermessiModelliECA' -Formato 'JSON' | Out-Null

Write-Host "Programma 04 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
