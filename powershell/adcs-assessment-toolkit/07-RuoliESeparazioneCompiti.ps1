<#
.SYNOPSIS
    Ruoli fidati e separazione dei compiti: chi gestisce la CA, chi gestisce i
    certificati, stato della separazione dei ruoli, amministratori locali
    dell'host della CA, appartenenza ai gruppi AD che ricoprono ruoli
    privilegiati sulla CA.
.DESCRIPTION
    Riusa Get-DescrittoreSicurezzaCA (Comune.ps1) per individuare i titolari
    dei diritti ManageCA e IssueManageCertificati. Per ciascuna identità
    trovata che risulta essere un gruppo di Active Directory (non un singolo
    utente), ne enumera i membri con Get-ADGroupMember: questo evita di dover
    indovinare nomi di gruppo specifici dell'organizzazione (non generici e
    non deducibili in anticipo), enumerando invece dinamicamente qualunque
    gruppo risulti effettivamente titolare di un ruolo sulla CA.
.NOTES
    IMPATTO: NESSUNO — SOLA LETTURA
    Prerequisiti: modulo ActiveDirectory (RSAT) per la risoluzione
    dell'appartenenza ai gruppi (facoltativo: senza di esso i titolari dei
    ruoli restano comunque elencati, solo senza espansione dei membri dei
    gruppi); diritto di lettura sulla CA e su AD.
    Privilegi minimi necessari: nessun privilegio amministrativo.
    Controlli dell'assessment coperti: 07 (Ruoli fidati e separazione dei
    compiti).
    Formato di uscita: record di evidenza normalizzati in JSON o CSV.
    Tempo di esecuzione atteso: pochi secondi, salvo gruppi con centinaia di
    membri o gerarchie di gruppi annidati profonde.
.PARAMETER PercorsoUscita
    Cartella già esistente in cui scrivere le uscite.
.PARAMETER Formato
    JSON o CSV.
.PARAMETER ConfigCA
    Stringa "NomeServer\NomeCA" da passare a GetCASecurity/certutil -getreg.
    Se specificato (CA remota), l'accertamento sugli amministratori locali
    dell'host viene saltato (richiederebbe accesso remoto non tentato da
    questo programma) e marcato "non applicabile".
.EXAMPLE
    .\07-RuoliESeparazioneCompiti.ps1 -PercorsoUscita C:\Evidenze\CA01
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

$nomeProgramma = '07-RuoliESeparazioneCompiti'
$riepilogo = Format-RiepilogoEsecuzione -NomeProgramma $nomeProgramma
$recordEvidenza = [System.Collections.Generic.List[object]]::new()

try {
    Test-CartellaUscita -PercorsoUscita $PercorsoUscita | Out-Null
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

$caLocale = [string]::IsNullOrWhiteSpace($ConfigCA)
$argomentiConfig = if ($caLocale) { @() } else { @('-config', $ConfigCA) }

# --- 07.01: titolari dei ruoli CA (Manage CA / Issue and Manage Certificates)
$riepilogo.AccertamentiTentati++
$esitoDescrittoreCA = Get-DescrittoreSicurezzaCA -ConfigCA $ConfigCA
$identitaConRuoli = @()
if ($esitoDescrittoreCA.Successo) {
    $identitaConRuoli = @($esitoDescrittoreCA.Voci | Where-Object { $_.ManageCA -or $_.IssueManageCertificati })
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.01' -Dominio 'RuoliCA' `
                -Accertamento 'Titolari dei ruoli Manage CA / Issue and Manage Certificates' `
                -Valore $identitaConRuoli -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
else {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.01' -Dominio 'RuoliCA' `
                -Accertamento 'Titolari dei ruoli Manage CA / Issue and Manage Certificates' `
                -Valore $esitoDescrittoreCA.Errore -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 07.02: separazione dei ruoli abilitata (RoleSeparationEnabled) --------
$riepilogo.AccertamentiTentati++
try {
    $risultato = Invoke-CertutilSolaLettura -Argomenti (@('-getreg', 'CA\RoleSeparationEnabled') + $argomentiConfig)
    if ($risultato.CodiceUscita -ne 0 -or $risultato.Errore) {
        throw "certutil -getreg CA\RoleSeparationEnabled ha restituito codice $($risultato.CodiceUscita): $($risultato.Errore)"
    }
    $rigaValore = $risultato.Output | Where-Object { $_ -match '=|REG_' } | Select-Object -First 1
    $valore = if ($rigaValore) { $rigaValore.Trim() } else { ($risultato.Output -join ' | ') }
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.02' -Dominio 'RuoliCA' `
                -Accertamento 'Separazione dei ruoli CA abilitata (RoleSeparationEnabled)' `
                -Valore $valore -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiRiusciti++
}
catch {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.02' -Dominio 'RuoliCA' `
                -Accertamento 'Separazione dei ruoli CA abilitata (RoleSeparationEnabled)' `
                -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 07.03: amministratori locali dell'host della CA -----------------------
$riepilogo.AccertamentiTentati++
if ($caLocale) {
    try {
        $membriAdmin = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.03' -Dominio 'RuoliSistema' `
                    -Accertamento 'Membri del gruppo Administrators locale sull host della CA' `
                    -Valore @($membriAdmin) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiRiusciti++
    }
    catch {
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.03' -Dominio 'RuoliSistema' `
                    -Accertamento 'Membri del gruppo Administrators locale sull host della CA' `
                    -Valore $_.Exception.Message -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}
else {
    $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.03' -Dominio 'RuoliSistema' `
                -Accertamento 'Membri del gruppo Administrators locale sull host della CA' `
                -Valore "CA remota (-ConfigCA '$ConfigCA'): eseguire questo programma direttamente sull host della CA per questo accertamento." `
                -Stato 'non applicabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
    $riepilogo.AccertamentiFalliti++
}

# --- 07.04: espansione dei gruppi AD titolari di ruoli sulla CA ------------
foreach ($voce in $identitaConRuoli) {
    $riepilogo.AccertamentiTentati++
    $identitaCompleta = $voce.Identita
    if ([string]::IsNullOrWhiteSpace($identitaCompleta)) {
        $riepilogo.AccertamentiFalliti++
        continue
    }
    $nomeAccount = ($identitaCompleta -split '\\')[-1]

    try {
        $membri = Get-ADGroupMember -Identity $nomeAccount -Recursive -ErrorAction Stop |
            Select-Object Name, SamAccountName, ObjectClass
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.04' -Dominio 'RuoliCA' `
                    -Accertamento "Membri (ricorsivi) del gruppo con ruolo sulla CA: $identitaCompleta" `
                    -Valore @($membri) -Stato 'rilevato' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiRiusciti++
    }
    catch {
        # Puo fallire perche l'identita e un singolo utente (non un gruppo),
        # perche il modulo ActiveDirectory non e disponibile, o per mancanza
        # di visibilita sull'oggetto: in tutti i casi si dichiara "non
        # verificabile" con il motivo, senza bloccare gli altri titolari.
        $recordEvidenza.Add((Format-RecordEvidenza -IdControllo '07.04' -Dominio 'RuoliCA' `
                    -Accertamento "Membri (ricorsivi) del gruppo con ruolo sulla CA: $identitaCompleta" `
                    -Valore "Non espandibile come gruppo AD (potrebbe essere un singolo utente, un gruppo locale, o il modulo ActiveDirectory non e disponibile): $($_.Exception.Message)" `
                    -Stato 'non verificabile' -Completezza 'completo' -StrategiaLettura 'n/d'))
        $riepilogo.AccertamentiFalliti++
    }
}

$riepilogo.RecordProdotti = $recordEvidenza.Count
$riepilogo = Complete-RiepilogoEsecuzione -Riepilogo $riepilogo

Export-Evidenza -Dati $recordEvidenza -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Evidenza_07_RuoliESeparazioneCompiti' -Formato $Formato | Out-Null
Export-Evidenza -Dati $riepilogo -PercorsoUscita $PercorsoUscita -NomeFileSenzaEstensione 'Riepilogo_07_RuoliESeparazioneCompiti' -Formato 'JSON' | Out-Null

Write-Host "Programma 07 completato. Record prodotti: $($recordEvidenza.Count). Uscite in: $PercorsoUscita"
