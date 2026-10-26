# ==============================================================================
# PROJET : SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# SCRIPT : Préparation de l'environnement et sécurisation WinRM (Parties 1 & 7)
# ==============================================================================

$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"

# 1. Autoriser l'exécution de scripts locaux
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# 2. Activer PowerShell Remoting et vérifier le service WinRM (Partie 1.4)
Enable-PSRemoting -Force
$WinRMService = Get-Service -Name WinRM
Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Cyan

# 3. Restreindre TrustedHosts uniquement aux IP présentes dans computers.txt (Partie 7.1 & 7.5)
if (Test-Path $ComputersFile) {
    $AllowedIPs = (Get-Content $ComputersFile | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
        ($_ -split ';')[1].Trim()
    }) -join ","
    
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $AllowedIPs -Force
    Write-Host "TrustedHosts configuré avec succès pour : $AllowedIPs" -ForegroundColor Green
} else {
    Write-Warning "Fichier computers.txt introuvable. Veuillez le créer avant de configurer TrustedHosts."
}

# 4. (Sur les postes cibles) Restreindre la règle de pare-feu WinRM à l'IP du poste d'administration (Partie 7.5)
# Remplacez 192.168.10.1 par l'adresse IP réelle de votre poste d'administration :
# Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress "192.168.10.1"