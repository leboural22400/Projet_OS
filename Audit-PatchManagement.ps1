#Requires -RunAsAdministrator
# ==============================================================================
# PROJET : SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# SCRIPT : Audit centralisé de Patch Management (Parties 2 à 7)
# Auteur : Martin Bourreau
#
# Usage :
#   .\Audit-PatchManagement.ps1
#   .\Audit-PatchManagement.ps1 -UserName svc-patch -JeaConfigurationName PatchManagementJEA
#   .\Audit-PatchManagement.ps1 -UseCurrentUser            (exécution planifiée, sans invite)
# ==============================================================================

param(
    [Parameter(Mandatory = $false, HelpMessage = "Compte utilisé pour les connexions distantes.")]
    [string]$UserName = "Administrateur",

    [Parameter(Mandatory = $false, HelpMessage = "Identifiants fournis directement (exécution non interactive).")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = "Utilise les identifiants de la session courante, sans invite.")]
    [switch]$UseCurrentUser,

    [Parameter(Mandatory = $false, HelpMessage = "Nom du point de terminaison JEA (ex : PatchManagementJEA).")]
    [string]$JeaConfigurationName = "",

    [Parameter(Mandatory = $false, HelpMessage = "Durée de conservation des archives horodatées, en jours (Partie 7.8).")]
    [int]$RetentionDays = 30
)

# --- 1. Variables de configuration et sécurisation des fichiers (Parties 7.4 & 7.8) ---
$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"
$RequiredPatchesFile = "$ScriptPath\required-patches.txt"

# Initialisation à partir des fichiers .example.txt si les fichiers locaux n'existent pas
if (-not (Test-Path $ComputersFile) -and (Test-Path "$ScriptPath\computers.example.txt")) {
    Copy-Item -Path "$ScriptPath\computers.example.txt" -Destination $ComputersFile
}
if (-not (Test-Path $RequiredPatchesFile) -and (Test-Path "$ScriptPath\required-patches.example.txt")) {
    Copy-Item -Path "$ScriptPath\required-patches.example.txt" -Destination $RequiredPatchesFile
}

$OutputDir = "$ScriptPath\Rapports"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# ACL : accès réservé aux Administrateurs (S-1-5-32-544) et à SYSTEM (S-1-5-18)
icacls $OutputDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
foreach ($ConfigFile in @($ComputersFile, $RequiredPatchesFile)) {
    if (Test-Path $ConfigFile) {
        icacls $ConfigFile /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
    }
}

# Horodatage à la seconde ; si une exécution a déjà utilisé cette seconde, on attend la suivante
# (les archives précédentes sont en lecture seule et ne doivent jamais être écrasées)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
while (Get-ChildItem -Path $OutputDir -Filter "*_$Timestamp.*" -File -ErrorAction SilentlyContinue) {
    Start-Sleep -Milliseconds 200
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}
$LogFile = "$OutputDir\PatchManager.log"
$LogFile_Hist = "$OutputDir\PatchManager_$Timestamp.log"

# Fichiers courants (noms exigés par l'énoncé)
$InventoryCSV = "$OutputDir\Hardware_Inventory.csv"
$PatchesCSV = "$OutputDir\PatchesInventory.csv"
$ComplianceCSV = "$OutputDir\ComplianceReport.csv"
$HtmlReport = "$OutputDir\SecurityReport.html"

# Copies horodatées (Partie 7.8)
$InventoryCSV_Hist = "$OutputDir\Hardware_Inventory_$Timestamp.csv"
$PatchesCSV_Hist = "$OutputDir\PatchesInventory_$Timestamp.csv"
$ComplianceCSV_Hist = "$OutputDir\ComplianceReport_$Timestamp.csv"
$HtmlReport_Hist = "$OutputDir\SecurityReport_$Timestamp.html"
$HashFile = "$OutputDir\Integrity_Hashes.sha256"

# Configuration e-mail (Partie 6.1) - serveur SMTP local de démo (Papercut / smtp4dev)
$SMTPServer = "localhost"
$EmailFrom = "patch-manager@entreprise.local"
$EmailTo = "admin@entreprise.local"

# --- 2. Journalisation au format exigé (Partie 5.4) ---
$Script:RunLogEntries = @()
Function Write-Log {
    param([string]$Message)
    $Date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $LogEntry = "$Date ; $Message"
    Write-Host $LogEntry
    $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    $Script:RunLogEntries += $LogEntry
}

Write-Log "Début de l'audit"

# --- 3. Partie 3.1 : correctifs installés sur la machine locale ---
Write-Host "`n=== PARTIE 3.1 : CORRECTIFS INSTALLES SUR LA MACHINE LOCALE ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Sort-Object InstalledOn -Descending | Format-Table -AutoSize

# --- 4. Lecture et validation des fichiers sources (Parties 1.3 & 4.2) ---
if (-not (Test-Path $ComputersFile) -or -not (Test-Path $RequiredPatchesFile)) {
    Write-Log "ERREUR ; Fichiers sources manquants (computers.txt ou required-patches.txt)"
    Exit
}

# Lignes vides, commentaires (#) et lignes sans ';' ignorés
$Computers = @(Get-Content $ComputersFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ';' } | ForEach-Object {
    $parts = $_ -split ';', 2
    if ($parts[0].Trim() -ne "" -and $parts[1].Trim() -ne "") {
        [PSCustomObject]@{
            Nom = $parts[0].Trim()
            IP  = $parts[1].Trim()
        }
    }
})

# Normalisation des KB (ajout du préfixe "KB" s'il a été omis)
$RequiredKBs = @(Get-Content $RequiredPatchesFile | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object {
    $clean = $_.Trim().ToUpper()
    if ($clean -ne "" -and $clean -notmatch '^KB') { "KB$clean" } else { $clean }
} | Where-Object { $_ -ne "" })

# Identifiants distants, sans déchiffrer le SecureString (Parties 6.1 & 7.3)
# -Credential et -UseCurrentUser permettent une exécution sans invite (tâche planifiée, tests automatisés)
$Cred = $null
if ($null -ne $Credential) {
    $Cred = $Credential
} elseif ($UseCurrentUser) {
    Write-Host "Utilisation des identifiants de la session courante." -ForegroundColor Yellow
} else {
    Write-Host "Authentification WinRM : saisissez le mot de passe ou cliquez sur 'Annuler' pour utiliser la session courante." -ForegroundColor Cyan
    try {
        $CredInput = Get-Credential -UserName $UserName -Message "Authentification WinRM (Annuler = session courante)" -ErrorAction Stop
        if ($null -ne $CredInput -and $CredInput.Password.Length -gt 0) {
            $Cred = $CredInput
        }
    } catch {
        Write-Host "Utilisation des identifiants de la session courante." -ForegroundColor Yellow
    }
}

# Tableaux de résultats
$GlobalHardware = @()
$GlobalPatches = @()
$GlobalPatchesSummary = @()
$GlobalCompliance = @()
$GlobalSecurityReport = @()

# --- 5. Boucle principale d'audit par machine ---
foreach ($PC in $Computers) {
    $IP = $PC.IP
    $Name = $PC.Nom
    $CheckDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $Status = $null
    $ErrMsg = $null
    $Session = $null

    # Test ICMP puis WinRM (repli sur Test-WSMan si l'ICMP est filtré)
    $PingOK = Test-Connection -ComputerName $IP -Count 1 -Quiet
    $WsmanOK = [bool](Test-WSMan -ComputerName $IP -ErrorAction SilentlyContinue)

    if ($PingOK -or $WsmanOK) {
        if ($WsmanOK) {
            try {
                $SessionParams = @{
                    ComputerName = $IP
                    ErrorAction  = "Stop"
                }
                if ($null -ne $Cred) {
                    $SessionParams.Add("Credential", $Cred)
                }
                if ($JeaConfigurationName -ne "") {
                    $SessionParams.Add("ConfigurationName", $JeaConfigurationName)
                }

                # Session unique ; commandes "nues" uniquement (compatible JEA / NoLanguage)
                $Session = New-PSSession @SessionParams

                # Partie 7.6 : une connexion par adresse IP ne peut pas utiliser Kerberos (Negotiate retombe sur NTLM).
                # Le protocole réellement utilisé se vérifie sur la cible (événement 4624, voir README).
                $AuthInfo = if ($IP -match '^\d{1,3}(\.\d{1,3}){3}$') { "Negotiate -> NTLM (connexion par adresse IP)" } else { "Negotiate (Kerberos possible en domaine)" }
                $EndpointInfo = if ($JeaConfigurationName -ne "") { $JeaConfigurationName } else { "Microsoft.PowerShell" }
                Write-Log "$Name ; Session ouverte ; Endpoint : $EndpointInfo ; Authentification : $AuthInfo"

                # --- PARTIE 2 : INVENTAIRE DU PARC ---
                $OS    = Invoke-Command -Session $Session -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem } -ErrorAction Stop
                $CS    = Invoke-Command -Session $Session -ScriptBlock { Get-CimInstance -ClassName Win32_ComputerSystem } -ErrorAction Stop
                $BIOS  = Invoke-Command -Session $Session -ScriptBlock { Get-CimInstance -ClassName Win32_BIOS } -ErrorAction Stop
                $Disks = Invoke-Command -Session $Session -ScriptBlock { Get-CimInstance -ClassName Win32_LogicalDisk } -ErrorAction Stop
                $WU    = Invoke-Command -Session $Session -ScriptBlock { Get-Service -Name wuauserv } -ErrorAction SilentlyContinue

                # --- PARTIE 3 : INVENTAIRE DES CORRECTIFS ---
                $RawPatches = @(Invoke-Command -Session $Session -ScriptBlock { Get-HotFix } -ErrorAction Stop)

                # Calculs réalisés localement sur le poste d'administration
                $SysDrive = if ($OS.SystemDrive) { $OS.SystemDrive } else { "C:" }
                $Disk = $Disks | Where-Object { $_.DeviceID -eq $SysDrive } | Select-Object -First 1
                $RamGB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                $FreeSpaceGB = if ($Disk) { [math]::Round($Disk.FreeSpace / 1GB, 2) } else { 0 }
                $WuStatus = if ($WU) { [string]$WU.Status } else { "Inconnu" }

                # Date d'installation : InstalledOn, ou à défaut InstallDate (format US MM/dd/yyyy)
                $Patches = @($RawPatches | ForEach-Object {
                    $Date = $_.InstalledOn
                    if (-not $Date -and $_.InstallDate) {
                        try { $Date = [datetime]::Parse($_.InstallDate, [System.Globalization.CultureInfo]::InvariantCulture) } catch { $Date = $null }
                    }
                    [PSCustomObject]@{
                        HotFixID    = $_.HotFixID
                        Description = $_.Description
                        InstalledOn = if ($Date) { [datetime]$Date } else { $null }
                        InstalledBy = $_.InstalledBy
                    }
                } | Sort-Object InstalledOn -Descending)

                # Synthèse des correctifs (Partie 3.6)
                $TotalMaj = $Patches.Count
                $DerniereMajObj = $Patches | Select-Object -First 1
                $DerniereMajDate = if ($DerniereMajObj.InstalledOn) { $DerniereMajObj.InstalledOn.ToString("dd/MM/yyyy") } else { "N/A" }
                $DerniereMajKB = if ($DerniereMajObj.HotFixID) { $DerniereMajObj.HotFixID } else { "Aucun" }
                $BootDateStr = if ($OS.LastBootUpTime) { ([datetime]$OS.LastBootUpTime).ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

                # --- PARTIE 4 : CONTROLE DE CONFORMITE ---
                $InstalledKBs = @($Patches.HotFixID | ForEach-Object { "$_".ToUpper() })
                $MissingKBs = @($RequiredKBs | Where-Object { $InstalledKBs -notcontains $_ })

                $NbMissing = $MissingKBs.Count
                $MissingKBsStr = $MissingKBs -join ", "
                $ComplianceState = if ($NbMissing -eq 0) { "CONFORME" } else { "NON CONFORME" }

                # Construction de tous les objets avant ajout (aucun doublon en cas d'exception)
                $HwObj = [PSCustomObject]@{
                    Poste             = $Name
                    Adresse_IP        = $IP
                    Nom_Reel          = $CS.Name
                    Modele            = $CS.Model
                    BIOS              = $BIOS.SMBIOSBIOSVersion
                    Windows           = $OS.Caption
                    Architecture      = $OS.OSArchitecture
                    RAM_GB            = $RamGB
                    Espace_Disque_GB  = $FreeSpaceGB
                    Dernier_Demarrage = $BootDateStr
                    Windows_Update    = $WuStatus
                    Total_KB          = $TotalMaj
                    Date_Derniere_KB  = $DerniereMajDate
                    Etat              = "Accessible"
                    Erreur            = "Aucune"
                }

                $SummaryObj = [PSCustomObject]@{
                    Poste                = $Name
                    Total_Correctifs     = $TotalMaj
                    Date_Plus_Recent     = $DerniereMajDate
                    Dernier_Correctif_KB = $DerniereMajKB
                }

                $CompObj = [PSCustomObject]@{
                    Poste               = $Name
                    KB_Requises         = $RequiredKBs.Count
                    Nb_KB_Manquantes    = $NbMissing
                    Liste_KB_Manquantes = if ($NbMissing -gt 0) { $MissingKBsStr } else { "Aucune" }
                    Etat                = $ComplianceState
                    DateControle        = $CheckDate
                }

                $SecObj = [PSCustomObject]@{
                    Poste               = $Name
                    Adresse_IP          = $IP
                    Accessibilite       = "Accessible"
                    Windows             = $OS.Caption
                    Dernier_Demarrage   = $BootDateStr
                    Windows_Update      = $WuStatus
                    KB_Requises         = $RequiredKBs.Count
                    Nb_KB_Manquantes    = $NbMissing
                    Liste_KB_Manquantes = if ($NbMissing -gt 0) { $MissingKBsStr } else { "Aucune" }
                    Etat_Conformite     = $ComplianceState
                    Detail_Erreur       = "Aucune"
                    Date_Controle       = $CheckDate
                }

                $PatchObjs = @($Patches | ForEach-Object {
                    [PSCustomObject]@{
                        Poste            = $Name
                        Adresse_IP       = $IP
                        KB               = $_.HotFixID
                        Description      = $_.Description
                        DateInstallation = $_.InstalledOn
                        InstallePar      = $_.InstalledBy
                    }
                })

                # Ajout atomique aux collections globales
                $GlobalHardware += $HwObj
                $GlobalPatchesSummary += $SummaryObj
                $GlobalCompliance += $CompObj
                $GlobalSecurityReport += $SecObj
                $GlobalPatches += $PatchObjs

                $Status = "Accessible"
                Write-Log "$Name ; Accessible"
                if ($ComplianceState -eq "CONFORME") {
                    Write-Log "$Name ; Conforme"
                } else {
                    Write-Log "$Name ; Non conforme ; $MissingKBsStr"
                }

            } catch {
                $ErrMsg = $_.Exception.Message
                Write-Log "$Name ; Erreur commande distante ; $ErrMsg"
                $Status = "Inaccessible"
            } finally {
                if ($null -ne $Session) {
                    Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Log "$Name ; WinRM inaccessible"
            $Status = "Inaccessible"
            $ErrMsg = "Service WinRM injoignable"
        }
    } else {
        Write-Log "$Name ; Ping et WinRM inaccessibles"
        $Status = "Inaccessible"
        $ErrMsg = "Machine injoignable (Ping et WinRM)"
    }

    # Poste inaccessible ou en erreur : enregistrement avec le motif (Parties 2.3, 4.3, 5.1)
    if ($Status -eq "Inaccessible") {
        $GlobalHardware += [PSCustomObject]@{
            Poste             = $Name
            Adresse_IP        = $IP
            Nom_Reel          = ""
            Modele            = ""
            BIOS              = ""
            Windows           = ""
            Architecture      = ""
            RAM_GB            = ""
            Espace_Disque_GB  = ""
            Dernier_Demarrage = ""
            Windows_Update    = ""
            Total_KB          = ""
            Date_Derniere_KB  = ""
            Etat              = "Inaccessible"
            Erreur            = $ErrMsg
        }

        $GlobalCompliance += [PSCustomObject]@{
            Poste               = $Name
            KB_Requises         = $RequiredKBs.Count
            Nb_KB_Manquantes    = ""
            Liste_KB_Manquantes = ""
            Etat                = "INACCESSIBLE"
            DateControle        = $CheckDate
        }

        $GlobalSecurityReport += [PSCustomObject]@{
            Poste               = $Name
            Adresse_IP          = $IP
            Accessibilite       = "Inaccessible"
            Windows             = "N/A"
            Dernier_Demarrage   = "N/A"
            Windows_Update      = "N/A"
            KB_Requises         = $RequiredKBs.Count
            Nb_KB_Manquantes    = "N/A"
            Liste_KB_Manquantes = "N/A"
            Etat_Conformite     = "INACCESSIBLE"
            Detail_Erreur       = $ErrMsg
            Date_Controle       = $CheckDate
        }
    }
}

# --- 6. Affichages console et exports CSV (Parties 2.4, 3.6, 4.3, 4.4, 4.5) ---
Write-Host "`n=== PARTIE 2.4 : TABLEAU RECAPITULATIF DE L'INVENTAIRE DU PARC ===" -ForegroundColor Cyan
$GlobalHardware | Select-Object Poste, Adresse_IP, Windows, Architecture, Dernier_Demarrage, Windows_Update, Etat, Erreur | Format-Table -AutoSize

Write-Host "=== PARTIE 3.6 : SYNTHESE DES CORRECTIFS PAR MACHINE ===" -ForegroundColor Cyan
$GlobalPatchesSummary | Format-Table -AutoSize

Write-Host "=== PARTIE 4.3 & 4.4 : RESULTATS DU CONTROLE DE CONFORMITE ===" -ForegroundColor Cyan
$GlobalCompliance | Format-Table -AutoSize -Wrap

$NonConformesList = @($GlobalCompliance | Where-Object Etat -eq "NON CONFORME")
if ($NonConformesList.Count -gt 0) {
    Write-Host "Détail des correctifs manquants sur les machines non conformes :" -ForegroundColor Yellow
    foreach ($NC in $NonConformesList) {
        Write-Host " - $($NC.Poste) ($($NC.DateControle)) : $($NC.Liste_KB_Manquantes)" -ForegroundColor Red
    }
    Write-Host ""
}

# Exports CSV (fichiers courants + copies horodatées)
$SortedPatches = $GlobalPatches | Sort-Object @{Expression = "Poste"; Ascending = $true}, @{Expression = "DateInstallation"; Descending = $true}

$GlobalHardware   | Export-Csv -Path $InventoryCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$SortedPatches    | Export-Csv -Path $PatchesCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$GlobalCompliance | Export-Csv -Path $ComplianceCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8

Copy-Item -Path $InventoryCSV -Destination $InventoryCSV_Hist -Force
Copy-Item -Path $PatchesCSV -Destination $PatchesCSV_Hist -Force
Copy-Item -Path $ComplianceCSV -Destination $ComplianceCSV_Hist -Force

# --- 7. Synthèse et rapport HTML (Parties 4.6 & 5) ---
$TotalPostes = $GlobalSecurityReport.Count
$PostesAccessibles = @($GlobalSecurityReport | Where-Object Accessibilite -eq "Accessible").Count
$PostesInaccessibles = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "INACCESSIBLE").Count
$PostesConformes = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "CONFORME").Count
$PostesNonConformes = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "NON CONFORME").Count

$TotalKBManquantes = 0
foreach ($Row in ($GlobalSecurityReport | Where-Object Accessibilite -eq "Accessible")) {
    $TotalKBManquantes += [int]$Row.Nb_KB_Manquantes
}

# Taux de conformité SANS les postes inaccessibles (Partie 4.6)
$TauxConformite = 0
if ($PostesAccessibles -gt 0) {
    $TauxConformite = [math]::Round(($PostesConformes / $PostesAccessibles) * 100, 2)
}

Write-Host "Taux global de conformité du parc (hors postes inaccessibles) : $TauxConformite %`n" -ForegroundColor Yellow

$HtmlHead = @"
<meta charset="UTF-8">
<title>Rapport de Sécurité Patch Management</title>
<style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 25px; }
    h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
    h2 { color: #34495e; margin-top: 30px; border-left: 5px solid #3498db; padding-left: 10px; }
    ul { background: white; padding: 15px 30px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); width: fit-content; }
    li { margin: 6px 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; background: white; font-size: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
    th { background-color: #2c3e50; color: white; }
    .CONFORME { background-color: #d4edda; color: #155724; font-weight: bold; }
    .NON { background-color: #f8d7da; color: #721c24; font-weight: bold; }
    .INACCESSIBLE { background-color: #fff3cd; color: #856404; font-weight: bold; }
</style>
"@

$HtmlBody = "<h1>Rapport de Sécurité - Patch Management</h1>"
$HtmlBody += "<p><strong>Date de génération :</strong> $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>"

# 5.2 Synthèse globale
$HtmlBody += "<h2>1. Synthèse Globale du Parc</h2>"
$HtmlBody += @"
<ul>
    <li>Nombre total de postes : <strong>$TotalPostes</strong></li>
    <li>Nombre de postes accessibles : <strong>$PostesAccessibles</strong></li>
    <li>Nombre de postes inaccessibles : <strong>$PostesInaccessibles</strong></li>
    <li>Nombre de postes conformes : <strong>$PostesConformes</strong></li>
    <li>Nombre de postes non conformes : <strong>$PostesNonConformes</strong></li>
    <li>Nombre total de correctifs manquants : <strong>$TotalKBManquantes</strong></li>
    <li>Taux de conformité (hors postes inaccessibles) : <strong>$TauxConformite %</strong></li>
</ul>
"@

# 5.2 (bis) Postes nécessitant une intervention
$PostesIntervention = @($GlobalSecurityReport | Where-Object Etat_Conformite -ne "CONFORME")
$HtmlBody += "<h2>2. Postes Nécessitant une Intervention</h2>"
if ($PostesIntervention.Count -gt 0) {
    $TableIntervention = $PostesIntervention | ConvertTo-Html -Fragment | Out-String
    $TableIntervention = $TableIntervention -replace '<td>NON CONFORME</td>', '<td class="NON">NON CONFORME</td>'
    $TableIntervention = $TableIntervention -replace '<td>INACCESSIBLE</td>', '<td class="INACCESSIBLE">INACCESSIBLE</td>'
    $HtmlBody += $TableIntervention
} else {
    $HtmlBody += "<p>Aucun poste ne nécessite d'intervention. L'ensemble du parc est conforme.</p>"
}

# 5.1 État détaillé
$HtmlBody += "<h2>3. État Détaillé du Parc</h2>"
$TableFull = $GlobalSecurityReport | ConvertTo-Html -Fragment | Out-String
$TableFull = $TableFull -replace '<td>CONFORME</td>', '<td class="CONFORME">CONFORME</td>'
$TableFull = $TableFull -replace '<td>NON CONFORME</td>', '<td class="NON">NON CONFORME</td>'
$TableFull = $TableFull -replace '<td>INACCESSIBLE</td>', '<td class="INACCESSIBLE">INACCESSIBLE</td>'
$HtmlBody += $TableFull

ConvertTo-Html -Head $HtmlHead -Body $HtmlBody | Out-File -FilePath $HtmlReport -Encoding UTF8
Copy-Item -Path $HtmlReport -Destination $HtmlReport_Hist -Force
Write-Log "Rapport généré"

# --- 8. Notification décidée à partir du rapport généré (Partie 6.1) ---
$AlertTriggered = @($GlobalSecurityReport | Where-Object Etat_Conformite -in "NON CONFORME", "INACCESSIBLE").Count -gt 0

if ($AlertTriggered) {
    $DateControleCourt = Get-Date -Format "dd/MM/yyyy"

    $EmailBody = @"
Objet : [PATCH MANAGEMENT] Anomalies détectées

Date du contrôle : $DateControleCourt

Postes contrôlés     : $TotalPostes
Postes non conformes : $PostesNonConformes
Postes inaccessibles : $PostesInaccessibles
"@

    foreach ($PosteAnomalie in $PostesIntervention) {
        $EmailBody += "`r`n`r`n$($PosteAnomalie.Poste) : $($PosteAnomalie.Etat_Conformite)"
        if ($PosteAnomalie.Etat_Conformite -eq "NON CONFORME" -and $PosteAnomalie.Liste_KB_Manquantes -ne "Aucune") {
            foreach ($kb in ($PosteAnomalie.Liste_KB_Manquantes -split ", ")) {
                $EmailBody += "`r`n        $kb manquante"
            }
        } elseif ($PosteAnomalie.Etat_Conformite -eq "INACCESSIBLE" -and $PosteAnomalie.Detail_Erreur) {
            # Ajout volontaire par rapport au modèle de l'énoncé : motif de l'inaccessibilité
            $EmailBody += "`r`n        Motif : $($PosteAnomalie.Detail_Erreur)"
        }
    }

    try {
        $MailParams = @{
            From        = $EmailFrom
            To          = $EmailTo
            Subject     = "[PATCH MANAGEMENT] Anomalies détectées"
            Body        = $EmailBody
            SmtpServer  = $SMTPServer
            Attachments = @($HtmlReport, $ComplianceCSV)
            Encoding    = [System.Text.Encoding]::UTF8
            ErrorAction = "Stop"
        }
        Send-MailMessage @MailParams
        Write-Log "Notification envoyée à $EmailTo"
    } catch {
        Write-Log "ERREUR ; Notification non envoyée ; $($_.Exception.Message)"
    }
} else {
    Write-Log "Aucune anomalie ; pas de notification"
}

# --- 9. Rotation des archives, journalisée (Partie 7.8) ---
$LimitDate = (Get-Date).AddDays(-$RetentionDays)
Get-ChildItem -Path $OutputDir -File | Where-Object {
    $_.Name -match '_\d{8}_\d{6}\.(csv|html|log)$' -and $_.LastWriteTime -lt $LimitDate
} | ForEach-Object {
    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    Write-Log "Rotation ; Archive supprimée (plus de $RetentionDays jours) ; $($_.Name)"
}

Write-Log "Fin de l'audit"

# --- 10. Journal figé, empreintes SHA-256 et verrouillage des archives (Partie 7.8) ---
# Copie figée du journal de CETTE exécution, après la dernière écriture
$Script:RunLogEntries | Out-File -FilePath $LogFile_Hist -Encoding UTF8

$GeneratedFiles = @($InventoryCSV_Hist, $PatchesCSV_Hist, $ComplianceCSV_Hist, $HtmlReport_Hist, $LogFile_Hist)
foreach ($File in $GeneratedFiles) {
    if (Test-Path $File) {
        $Hash = Get-FileHash -Path $File -Algorithm SHA256
        "$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') ; $($Hash.Algorithm) ; $($Hash.Hash) ; $(Split-Path $File -Leaf)" | Out-File -FilePath $HashFile -Append -Encoding UTF8
        # Archives en lecture seule (jamais le journal actif PatchManager.log)
        Set-ItemProperty -Path $File -Name IsReadOnly -Value $true
    }
}

# --- 11. Vérification affichée des droits d'accès (Partie 7.4) ---
Write-Host "`n=== PARTIE 7.4 : DROITS D'ACCES SUR LES FICHIERS DE LA SOLUTION ===" -ForegroundColor Cyan
foreach ($Path in @($OutputDir, $ComputersFile, $RequiredPatchesFile)) {
    if (Test-Path $Path) {
        Write-Host $Path -ForegroundColor Yellow
        (Get-Acl -Path $Path).Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited | Format-Table -AutoSize
    }
}
