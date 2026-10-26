#Requires -RunAsAdministrator
# ==============================================================================
# PROJET : SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# SCRIPT : Audit centralisé de Patch Management (Parties 2 à 7)
# Auteur : Martin Bourreau
# ==============================================================================

param(
    [string]$JeaConfigurationName = "" # Optionnel : ex. "PatchManagementJEA" (Partie 7.7)
)

# --- 1. Variables de configuration et sécurisation des fichiers (Parties 7.4 & 7.8) ---
$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"
$RequiredPatchesFile = "$ScriptPath\required-patches.txt"

$OutputDir = "$ScriptPath\Rapports"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Restriction des accès ACL (Administrateurs S-1-5-32-544 et SYSTEM S-1-5-18) sur le dossier Rapports et les fichiers de configuration
icacls $OutputDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
foreach ($ConfigFile in @($ComputersFile, $RequiredPatchesFile)) {
    if (Test-Path $ConfigFile) {
        icacls $ConfigFile /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
    }
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile = "$OutputDir\PatchManager.log"

# Fichiers courants (noms exigés par l'énoncé)
$InventoryCSV = "$OutputDir\Hardware_Inventory.csv"
$PatchesCSV = "$OutputDir\PatchesInventory.csv"
$ComplianceCSV = "$OutputDir\ComplianceReport.csv"
$HtmlReport = "$OutputDir\SecurityReport.html"

# Copies horodatées pour conserver l'historique (Partie 7.8)
$InventoryCSV_Hist = "$OutputDir\Hardware_Inventory_$Timestamp.csv"
$PatchesCSV_Hist = "$OutputDir\PatchesInventory_$Timestamp.csv"
$ComplianceCSV_Hist = "$OutputDir\ComplianceReport_$Timestamp.csv"
$HtmlReport_Hist = "$OutputDir\SecurityReport_$Timestamp.html"
$HashFile = "$OutputDir\Integrity_Hashes.sha256"

# Configuration Email (Partie 6.1 - localhost pour serveur SMTP local de démo type Papercut / smtp4dev)
$SMTPServer = "localhost"
$EmailFrom = "patch-manager@entreprise.local"
$EmailTo = "admin@entreprise.local"

# --- 2. Fonction de Journalisation au format exigé (Partie 5.4) ---
Function Write-Log {
    param([string]$Message)
    $Date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $LogEntry = "$Date ; $Message"
    Write-Host $LogEntry
    $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "Début de l'audit"

# --- 3. Partie 3.1 : Affichage des correctifs installés sur la machine locale ---
Write-Host "`n=== PARTIE 3.1 : CORRECTIFS INSTALLES SUR LA MACHINE LOCALE ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Sort-Object InstalledOn -Descending | Format-Table -AutoSize

# --- 4. Lecture et validation des fichiers sources (Parties 1.3 & 4.2) ---
if (-not (Test-Path $ComputersFile) -or -not (Test-Path $RequiredPatchesFile)) {
    Write-Log "ERREUR ; Fichiers sources manquants (computers.txt ou required-patches.txt)"
    Exit
}

# Ignore les lignes vides, les commentaires (#) et les lignes mal formées sans ';'
$Computers = @(Get-Content $ComputersFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ';' } | ForEach-Object {
    $parts = $_ -split ';', 2
    if ($parts[0].Trim() -ne "" -and $parts[1].Trim() -ne "") {
        [PSCustomObject]@{
            Nom = $parts[0].Trim()
            IP  = $parts[1].Trim()
        }
    }
})

$RequiredKBs = @(Get-Content $RequiredPatchesFile | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

# Demande des identifiants d'administration distante (Parties 6.1 & 7.3)
Write-Host "Authentification WinRM : saisissez le mot de passe ou cliquez sur 'Annuler' pour utiliser la session courante." -ForegroundColor Cyan
$Cred = $null
try {
    $CredInput = Get-Credential -UserName "Administrateur" -Message "Authentification WinRM (Annuler = session courante)" -ErrorAction Stop
    if ($null -ne $CredInput -and $CredInput.GetNetworkCredential().Password -ne "") {
        $Cred = $CredInput
    }
} catch {
    Write-Host "Utilisation des identifiants de la session courante." -ForegroundColor Yellow
}

# Tableaux pour stocker les résultats
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

    # Test de connectivité ICMP et test WinRM (avec repli sur Test-WSMan si l'ICMP est filtré par le pare-feu)
    $PingOK = Test-Connection -ComputerName $IP -Count 1 -Quiet
    $WsmanOK = [bool](Test-WSMan -ComputerName $IP -ErrorAction SilentlyContinue)

    if ($PingOK -or $WsmanOK) {
        if ($WsmanOK) {
            try {
                $InvokeParams = @{
                    ComputerName = $IP
                    ErrorAction  = "Stop"
                }
                if ($null -ne $Cred) {
                    $InvokeParams.Add("Credential", $Cred)
                }
                if ($JeaConfigurationName -ne "") {
                    $InvokeParams.Add("ConfigurationName", $JeaConfigurationName)
                }

                # --- PARTIE 2 : INVENTAIRE DU PARC ---
                $SysInfo = Invoke-Command @InvokeParams -ScriptBlock {
                    $OS = Get-CimInstance Win32_OperatingSystem
                    $CS = Get-CimInstance Win32_ComputerSystem
                    $BIOS = Get-CimInstance Win32_BIOS
                    $SysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
                    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$SysDrive'"
                    $WU = Get-Service -Name wuauserv -ErrorAction SilentlyContinue

                    [PSCustomObject]@{
                        NomPoste       = $CS.Name
                        Modele         = $CS.Model
                        Bios           = $BIOS.SMBIOSBIOSVersion
                        OSVersion      = $OS.Caption
                        Architecture   = $OS.OSArchitecture
                        DernierBoot    = $OS.LastBootUpTime
                        RAM_GB         = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                        EspaceLibre_GB = [math]::Round($Disk.FreeSpace / 1GB, 2)
                        WU_Statut      = if ($WU) { [string]$WU.Status } else { "Inconnu" }
                    }
                }

                # --- PARTIE 3 : INVENTAIRE DES CORRECTIFS ---
                $Patches = @(Invoke-Command @InvokeParams -ScriptBlock {
                    Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
                })

                Write-Log "$Name ; Accessible"
                $Status = "Accessible"

                # Tri des correctifs par date d'installation décroissante (Partie 3.6)
                $Patches = @($Patches | Sort-Object InstalledOn -Descending)
                $TotalMaj = $Patches.Count
                $DerniereMajObj = $Patches | Select-Object -First 1
                $DerniereMajDate = if ($DerniereMajObj.InstalledOn) { ([datetime]$DerniereMajObj.InstalledOn).ToString("dd/MM/yyyy") } else { "N/A" }
                $DerniereMajKB = if ($DerniereMajObj.HotFixID) { $DerniereMajObj.HotFixID } else { "Aucun" }
                $BootDateStr = if ($SysInfo.DernierBoot) { ([datetime]$SysInfo.DernierBoot).ToString("dd/MM/yyyy HH:mm") } else { "N/A" }

                # Inventaire matériel complet (Partie 2.2 & 2.3)
                $GlobalHardware += [PSCustomObject]@{
                    Poste             = $Name
                    Adresse_IP        = $IP
                    Nom_Reel          = $SysInfo.NomPoste
                    Modele            = $SysInfo.Modele
                    BIOS              = $SysInfo.Bios
                    Windows           = $SysInfo.OSVersion
                    Architecture      = $SysInfo.Architecture
                    RAM_GB            = $SysInfo.RAM_GB
                    Espace_Disque_GB  = $SysInfo.EspaceLibre_GB
                    Dernier_Demarrage = $BootDateStr
                    Windows_Update    = $SysInfo.WU_Statut
                    Total_KB          = $TotalMaj
                    Date_Derniere_KB  = $DerniereMajDate
                    Etat              = $Status
                    Erreur            = "Aucune"
                }

                # Synthèse des correctifs par machine (Partie 3.6)
                $GlobalPatchesSummary += [PSCustomObject]@{
                    Poste                = $Name
                    Total_Correctifs     = $TotalMaj
                    Date_Plus_Recent     = $DerniereMajDate
                    Dernier_Correctif_KB = $DerniereMajKB
                }

                # Inventaire global des correctifs (Partie 3.2 & 3.5)
                foreach ($Patch in $Patches) {
                    $GlobalPatches += [PSCustomObject]@{
                        Poste            = $Name
                        Adresse_IP       = $IP
                        KB               = $Patch.HotFixID
                        Description      = $Patch.Description
                        DateInstallation = $Patch.InstalledOn
                        InstallePar      = $Patch.InstalledBy
                    }
                }

                # --- PARTIE 4 : CONTROLE DE CONFORMITE ---
                $InstalledKBs = @($Patches.HotFixID)
                $MissingKBs = @()

                foreach ($ReqKB in $RequiredKBs) {
                    if ($InstalledKBs -notcontains $ReqKB) {
                        $MissingKBs += $ReqKB
                    }
                }

                $NbMissing = $MissingKBs.Count
                $MissingKBsStr = $MissingKBs -join ", "

                if ($NbMissing -eq 0) {
                    $ComplianceState = "CONFORME"
                    Write-Log "$Name ; Conforme"
                } else {
                    $ComplianceState = "NON CONFORME"
                    Write-Log "$Name ; Non conforme ; $MissingKBsStr"
                }

                $GlobalCompliance += [PSCustomObject]@{
                    Poste               = $Name
                    KB_Requises         = $RequiredKBs.Count
                    Nb_KB_Manquantes    = $NbMissing
                    Liste_KB_Manquantes = if ($NbMissing -gt 0) { $MissingKBsStr } else { "Aucune" }
                    Etat                = $ComplianceState
                    DateControle        = $CheckDate
                }

                $GlobalSecurityReport += [PSCustomObject]@{
                    Poste               = $Name
                    Adresse_IP          = $IP
                    Accessibilite       = $Status
                    Windows             = $SysInfo.OSVersion
                    Dernier_Demarrage   = $BootDateStr
                    Windows_Update      = $SysInfo.WU_Statut
                    KB_Requises         = $RequiredKBs.Count
                    Nb_KB_Manquantes    = $NbMissing
                    Liste_KB_Manquantes = if ($NbMissing -gt 0) { $MissingKBsStr } else { "Aucune" }
                    Etat_Conformite     = $ComplianceState
                    Date_Controle       = $CheckDate
                }

            } catch {
                $ErrMsg = $_.Exception.Message
                Write-Log "$Name ; Erreur commande distante ; $ErrMsg"
                $Status = "Inaccessible"
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

    # Si la machine est inaccessible, remplissage avec l'état correspondant (Parties 2.3, 4.3, 5.1)
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
            Date_Controle       = $CheckDate
        }
    }
}

# --- 6. Affichages récapitulatifs en console et Exports CSV (Parties 2.4, 3.6, 4.3, 4.4, 4.5) ---
Write-Host "`n=== PARTIE 2.4 : TABLEAU RECAPITULATIF DE L'INVENTAIRE DU PARC ===" -ForegroundColor Cyan
$GlobalHardware | Select-Object Poste, Adresse_IP, Windows, Architecture, Dernier_Demarrage, Windows_Update, Etat | Format-Table -AutoSize

Write-Host "=== PARTIE 3.6 : SYNTHESE DES CORRECTIFS PAR MACHINE ===" -ForegroundColor Cyan
$GlobalPatchesSummary | Format-Table -AutoSize

Write-Host "=== PARTIE 4.3 & 4.4 : RESULTATS DU CONTROLE DE CONFORMITE ===" -ForegroundColor Cyan
$GlobalCompliance | Format-Table -AutoSize -Wrap

# Affichage explicite sans troncature des correctifs manquants par poste non conforme (Partie 4.4)
$NonConformesList = @($GlobalCompliance | Where-Object Etat -eq "NON CONFORME")
if ($NonConformesList.Count -gt 0) {
    Write-Host "Détail des correctifs manquants sur les machines non conformes :" -ForegroundColor Yellow
    foreach ($NC in $NonConformesList) {
        Write-Host " - $($NC.Poste) ($($NC.DateControle)) : $($NC.Liste_KB_Manquantes)" -ForegroundColor Red
    }
    Write-Host ""
}

# Exportation CSV (fichiers standards + copies horodatées pour l'historique Partie 7.8)
$SortedPatches = $GlobalPatches | Sort-Object @{Expression="Poste"; Ascending=$true}, @{Expression="DateInstallation"; Descending=$true}

$GlobalHardware | Export-Csv -Path $InventoryCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$SortedPatches  | Export-Csv -Path $PatchesCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$GlobalCompliance | Export-Csv -Path $ComplianceCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8

Copy-Item -Path $InventoryCSV -Destination $InventoryCSV_Hist -Force
Copy-Item -Path $PatchesCSV -Destination $PatchesCSV_Hist -Force
Copy-Item -Path $ComplianceCSV -Destination $ComplianceCSV_Hist -Force

# --- 7. Calculs de synthèse et génération du Rapport HTML (Parties 4.6 & 5) ---
$TotalPostes = $GlobalSecurityReport.Count
$PostesAccessibles = @($GlobalSecurityReport | Where-Object Accessibilite -eq "Accessible").Count
$PostesInaccessibles = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "INACCESSIBLE").Count
$PostesConformes = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "CONFORME").Count
$PostesNonConformes = @($GlobalSecurityReport | Where-Object Etat_Conformite -eq "NON CONFORME").Count

$TotalKBManquantes = 0
foreach ($Row in ($GlobalSecurityReport | Where-Object Accessibilite -eq "Accessible")) {
    $TotalKBManquantes += [int]$Row.Nb_KB_Manquantes
}

# Taux de conformité calculé SANS inclure les postes inaccessibles (Partie 4.6)
$TauxConformite = 0
if ($PostesAccessibles -gt 0) {
    $TauxConformite = [math]::Round(($PostesConformes / $PostesAccessibles) * 100, 2)
}

Write-Host "Taux global de conformité du parc (hors postes inaccessibles) : $TauxConformite %`n" -ForegroundColor Yellow

# Construction du rapport HTML avec <title> directement dans <head> (Partie 5.3)
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

# 5.2 Synthèse globale du parc
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

# 5.2 (bis) Section recensant uniquement les postes nécessitant une intervention
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

# 5.1 Tableau complet du rapport de sécurité
$HtmlBody += "<h2>3. État Détaillé du Parc</h2>"
$TableFull = $GlobalSecurityReport | ConvertTo-Html -Fragment | Out-String
$TableFull = $TableFull -replace '<td>CONFORME</td>', '<td class="CONFORME">CONFORME</td>'
$TableFull = $TableFull -replace '<td>NON CONFORME</td>', '<td class="NON">NON CONFORME</td>'
$TableFull = $TableFull -replace '<td>INACCESSIBLE</td>', '<td class="INACCESSIBLE">INACCESSIBLE</td>'
$HtmlBody += $TableFull

ConvertTo-Html -Head $HtmlHead -Body $HtmlBody | Out-File -FilePath $HtmlReport -Encoding UTF8
Copy-Item -Path $HtmlReport -Destination $HtmlReport_Hist -Force
Write-Log "Rapport généré"

# Calcul et sauvegarde des empreintes SHA-256 pour garantir l'intégrité des rapports (Partie 7.8)
$GeneratedFiles = @($InventoryCSV_Hist, $PatchesCSV_Hist, $ComplianceCSV_Hist, $HtmlReport_Hist, $LogFile)
foreach ($File in $GeneratedFiles) {
    if (Test-Path $File) {
        $Hash = Get-FileHash -Path $File -Algorithm SHA256
        "$(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') ; $($Hash.Algorithm) ; $($Hash.Hash) ; $(Split-Path $File -Leaf)" | Out-File -FilePath $HashFile -Append -Encoding UTF8
    }
}

# --- 8. Notification automatique déterminée à partir du rapport généré (Partie 6.1) ---
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
        Write-Log "ERREUR ; Notification non envoyée"
    }
} else {
    Write-Log "Aucune anomalie ; pas de notification"
}

Write-Log "Fin de l'audit"