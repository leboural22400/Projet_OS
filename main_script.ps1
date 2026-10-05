# ==============================================================================
# PROJET: SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# Auteur: [Votre Nom]
# ==============================================================================

# --- 1. Variables de configuration ---
$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"
$RequiredPatchesFile = "$ScriptPath\required-patches.txt"
$LogFile = "$ScriptPath\Patch_Manager.log"
$InventoryCSV = "$ScriptPath\Hardware_Inventory.csv"
$PatchesCSV = "$ScriptPath\Patches_Inventory.csv"
$ComplianceCSV = "$ScriptPath\ComplianceReport.csv"
$HtmlReport = "$ScriptPath\SecurityReport.html"

# Configuration Email (À adapter)
$SMTPServer = "smtp.votre-serveur.com"
$EmailFrom = "admin@entreprise.com"
$EmailTo = "admin-sys@entreprise.com"
$AlertTriggered = $false # Passera à $true si un poste est non conforme

# --- 2. Fonction de Journalisation (Logging) ---
Function Write-Log {
    param([string]$Message)
    $Date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $LogEntry = "[$Date] - $Message"
    Write-Host $LogEntry
    $LogEntry | Out-File -FilePath $LogFile -Append
}

Write-Log "DÉMARRAGE de l'audit de Patch Management."

# --- 3. Lecture des fichiers sources ---
if (-not (Test-Path $ComputersFile) -or -not (Test-Path $RequiredPatchesFile)) {
    Write-Log "ERREUR : Fichiers sources manquants (computers.txt ou required-patches.txt)."
    Exit
}

$Computers = Get-Content $ComputersFile | ForEach-Object {
    $parts = $_ -split ';'
    [PSCustomObject]@{ Nom = $parts[0]; IP = $parts[1] }
}
$RequiredKBs = Get-Content $RequiredPatchesFile | Where-Object { $_ -ne "" }

# Tableaux pour stocker les résultats
$GlobalHardware = @()
$GlobalPatches = @()
$GlobalCompliance = @()

# --- 4. Boucle principale d'audit par machine ---
foreach ($PC in $Computers) {
    $IP = $PC.IP
    $Name = $PC.Nom
    Write-Log "Analyse de la machine : $Name ($IP)"

    # Test de connectivité (Ping)
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet) {
        
        # Test de WinRM (PowerShell Remoting)
        if (Test-WSMan -ComputerName $IP -ErrorAction SilentlyContinue) {
            Write-Log "--> $Name : Accessible via WinRM."
            $Status = "Accessible"

            # --- PARTIE 2 : INVENTAIRE DU PARC ---
            $SysInfo = Invoke-Command -ComputerName $IP -ScriptBlock {
                $OS = Get-CimInstance Win32_OperatingSystem
                $CS = Get-CimInstance Win32_ComputerSystem
                $BIOS = Get-CimInstance Win32_BIOS
                $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
                $WU = Get-Service -Name wuauserv
                
                [PSCustomObject]@{
                    Modele = $CS.Model
                    Bios = $BIOS.SMBIOSBIOSVersion
                    OSVersion = $OS.Caption
                    Architecture = $OS.OSArchitecture
                    DernierBoot = $OS.LastBootUpTime
                    RAM_GB = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
                    EspaceLibre_GB = [math]::Round($Disk.FreeSpace / 1GB, 2)
                    WU_Statut = $WU.Status
                }
            } -ErrorAction SilentlyContinue

            # --- PARTIE 3 : INVENTAIRE DES CORRECTIFS ---
            $Patches = Invoke-Command -ComputerName $IP -ScriptBlock {
                Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
            } -ErrorAction SilentlyContinue

            # Tri des correctifs par date décroissante
            $Patches = $Patches | Sort-Object InstalledOn -Descending
            $DerniereMaj = ($Patches | Select-Object -First 1).InstalledOn
            $TotalMaj = $Patches.Count

            # Ajout à l'inventaire matériel global
            $GlobalHardware += [PSCustomObject]@{
                Poste = $Name; IP = $IP; OS = $SysInfo.OSVersion; Arch = $SysInfo.Architecture; 
                DernierDemarrage = $SysInfo.DernierBoot; Service_WU = $SysInfo.WU_Statut; 
                Total_KB = $TotalMaj; Date_Derniere_KB = $DerniereMaj; Etat = $Status
            }

            # Ajout à l'inventaire des correctifs global
            foreach ($Patch in $Patches) {
                $GlobalPatches += [PSCustomObject]@{
                    Poste = $Name; IP = $IP; KB = $Patch.HotFixID; 
                    Description = $Patch.Description; DateInstallation = $Patch.InstalledOn
                }
            }

            # --- PARTIE 4 : CONTROLE DE CONFORMITE ---
            $InstalledKBs = $Patches.HotFixID
            $MissingKBs = @()
            
            foreach ($ReqKB in $RequiredKBs) {
                if ($InstalledKBs -notcontains $ReqKB) {
                    $MissingKBs += $ReqKB
                }
            }

            if ($MissingKBs.Count -eq 0) {
                $ComplianceState = "CONFORME"
            } else {
                $ComplianceState = "NON CONFORME"
                $AlertTriggered = $true
            }

            $GlobalCompliance += [PSCustomObject]@{
                Poste = $Name; KB_Requises = $RequiredKBs.Count; 
                KB_Manquantes = ($MissingKBs -join ", "); Etat = $ComplianceState; DateControle = (Get-Date)
            }

        } else {
            Write-Log "--> $Name : Ping OK mais Inaccessible via WinRM (Vérifier le service/pare-feu)."
            $Status = "Inaccessible WinRM"
            $AlertTriggered = $true
        }
    } else {
        Write-Log "--> $Name : Inaccessible (Échec Ping)."
        $Status = "Inaccessible Ping"
        $AlertTriggered = $true
    }

    # Si la machine est inaccessible, on remplit les tableaux avec des valeurs nulles/vides
    if ($Status -like "Inaccessible*") {
        $GlobalHardware += [PSCustomObject]@{ Poste=$Name; IP=$IP; OS="N/A"; Arch="N/A"; DernierDemarrage="N/A"; Service_WU="N/A"; Total_KB="N/A"; Date_Derniere_KB="N/A"; Etat=$Status }
        $GlobalCompliance += [PSCustomObject]@{ Poste=$Name; KB_Requises=$RequiredKBs.Count; KB_Manquantes="N/A"; Etat="INACCESSIBLE"; DateControle=(Get-Date) }
    }
}

# --- 5. Exportation en fichiers CSV ---
Write-Log "Exportation des données vers CSV..."
$GlobalHardware | Export-Csv -Path $InventoryCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$GlobalPatches | Sort-Object Poste, DateInstallation -Descending | Export-Csv -Path $PatchesCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8
$GlobalCompliance | Export-Csv -Path $ComplianceCSV -NoTypeInformation -Delimiter ";" -Encoding UTF8

# --- 6. Génération du Rapport HTML (Partie 6) ---
Write-Log "Génération du rapport de sécurité HTML..."

$HtmlHead = @"
<style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 20px; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #34495e; margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; background: white; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: center; }
    th { background-color: #3498db; color: white; }
    .CONFORME { background-color: #d4edda; color: #155724; font-weight: bold; }
    .NON { background-color: #f8d7da; color: #721c24; font-weight: bold; } /* NON CONFORME */
    .INACCESSIBLE { background-color: #fff3cd; color: #856404; font-weight: bold; }
</style>
"@

# Calculs de synthèse
$TotalPostes = $GlobalCompliance.Count
$Conformes = ($GlobalCompliance | Where-Object Etat -eq "CONFORME").Count
$TauxConformite = 0
if ($TotalPostes -gt 0) { $TauxConformite = [math]::Round(($Conformes / $TotalPostes) * 100, 2) }

$HtmlBody = "<h1>Rapport de Sécurité - Patch Management</h1>"
$HtmlBody += "<p><strong>Date du scan :</strong> $(Get-Date)</p>"
$HtmlBody += "<h2>Synthèse du Parc</h2>"
$HtmlBody += "<ul><li>Total des postes : $TotalPostes</li><li>Postes Conformes : $Conformes</li><li><strong>Taux de conformité : $TauxConformite %</strong></li></ul>"

$HtmlBody += "<h2>Détails de Conformité</h2>"
$TableHTML = $GlobalCompliance | ConvertTo-Html -Fragment | Out-String
# Application des classes CSS pour les couleurs
$TableHTML = $TableHTML -replace '<td>CONFORME</td>', '<td class="CONFORME">CONFORME</td>'
$TableHTML = $TableHTML -replace '<td>NON CONFORME</td>', '<td class="NON">NON CONFORME</td>'
$TableHTML = $TableHTML -replace '<td>INACCESSIBLE</td>', '<td class="INACCESSIBLE">INACCESSIBLE</td>'

$HtmlBody += $TableHTML

# Assemblage et sauvegarde du HTML
ConvertTo-Html -Head $HtmlHead -Body $HtmlBody | Out-File $HtmlReport

# --- 7. Envoi d'email en cas d'anomalie (Partie 7) ---
if ($AlertTriggered) {
    Write-Log "Anomalie(s) détectée(s) : Envoi de l'alerte e-mail à l'administrateur."
    try {
        # Note: Adaptez SMTPServer, From et To avec vos identifiants pour que l'email parte réellement
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "ALERTE: Postes non conformes ou inaccessibles" -Body "Veuillez trouver le rapport de sécurité ci-joint. Certains postes nécessitent votre attention." -SmtpServer $SMTPServer -Attachments $HtmlReport, $ComplianceCSV -ErrorAction Stop
        Write-Log "E-mail envoyé avec succès."
    } catch {
        Write-Log "Erreur lors de l'envoi de l'e-mail (Vérifiez la config SMTP) : $_"
    }
} else {
    Write-Log "Aucune anomalie. Le parc est à 100% conforme. Pas d'e-mail envoyé."
}

Write-Log "FIN de l'audit de Patch Management."