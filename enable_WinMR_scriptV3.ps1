#Requires -RunAsAdministrator
# ==============================================================================
# PROJET : SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# SCRIPT : Préparation de l'environnement et sécurisation WinRM (Parties 1 & 7)
# Auteur : Martin Bourreau
# ==============================================================================

param(
    [Parameter(Mandatory=$true, HelpMessage="Indiquez 'Admin' sur le poste central ou 'Cible' sur les postes supervisés.")]
    [ValidateSet("Admin", "Cible")]
    [string]$Role,

    [Parameter(Mandatory=$false, HelpMessage="Adresse IP du poste d'administration (pour filtrer le pare-feu sur la cible).")]
    [string]$AdminIP = "Any",

    [Parameter(Mandatory=$false, HelpMessage="Active le point de terminaison JEA (Partie 7.7).")]
    [switch]$RegisterJEA
)

$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"

# 1. Autoriser l'exécution de scripts locaux
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

if ($Role -eq "Admin") {
    Write-Host "=== CONFIGURATION DU POSTE D'ADMINISTRATION ===" -ForegroundColor Cyan

    # Démarrage du service client WinRM
    Start-Service -Name WinRM
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    # Restriction de TrustedHosts uniquement aux IP valides présentes dans computers.txt (Parties 7.1 & 7.5)
    if (Test-Path $ComputersFile) {
        $AllowedIPs = @(Get-Content $ComputersFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ';' } | ForEach-Object {
            ($_ -split ';', 2)[1].Trim()
        } | Where-Object { $_ -ne "" }) -join ","

        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $AllowedIPs -Force
        Write-Host "TrustedHosts restreint aux adresses IP du parc : $AllowedIPs" -ForegroundColor Green
    } else {
        Write-Warning "Fichier computers.txt introuvable dans $ScriptPath."
    }
}

if ($Role -eq "Cible") {
    Write-Host "=== CONFIGURATION DU POSTE CIBLE SUPERVISE ===" -ForegroundColor Cyan

    # 1. Activation de PowerShell Remoting même si la VM est sur un profil réseau Public (Partie 1.4)
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    # 2. Autoriser le Ping ICMP entrant pour Test-Connection (Partie 1.1 & 2.1)
    Enable-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" -ErrorAction SilentlyContinue
    Write-Host "Règle pare-feu ICMPv4 Echo Request activée." -ForegroundColor Green

    # 3. Restreindre la règle pare-feu WinRM à l'IP du poste d'administration (Partie 7.5)
    if ($AdminIP -ne "Any" -and $AdminIP -ne "") {
        Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress $AdminIP -ErrorAction SilentlyContinue
        Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-NoScope" -RemoteAddress $AdminIP -ErrorAction SilentlyContinue
        Write-Host "Pare-feu WinRM (port 5985) restreint à l'adresse IP admin : $AdminIP" -ForegroundColor Green
    }

    # 4. Autoriser l'administration distante en Workgroup pour les comptes administrateurs locaux (UAC distant)
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                     -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force | Out-Null

    # 5. Vérification des utilisateurs autorisés à ouvrir une session distante (Partie 7.2)
    Write-Host "`n--- Partie 7.2 : Permissions des sessions distantes (PSSessionConfiguration) ---" -ForegroundColor Yellow
    Get-PSSessionConfiguration | Select-Object Name, Permission | Format-List

    Write-Host "--- Partie 7.2 : Membres du groupe 'Utilisateurs de gestion à distance' (SID S-1-5-32-580) ---" -ForegroundColor Yellow
    $RMGroup = Get-LocalGroup -SID "S-1-5-32-580"
    Get-LocalGroupMember -Group $RMGroup | Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

    # 6. Enregistrement optionnel du profil JEA de moindre privilège (Parties 7.3 & 7.7)
    $JeaFile = "$ScriptPath\PatchManagementJEA.pssc"
    if ($RegisterJEA -and (Test-Path $JeaFile)) {
        if (Get-PSSessionConfiguration -Name "PatchManagementJEA" -ErrorAction SilentlyContinue) {
            Unregister-PSSessionConfiguration -Name "PatchManagementJEA" -Force
        }
        Register-PSSessionConfiguration -Name "PatchManagementJEA" -Path $JeaFile -Force
        Restart-Service WinRM
        Write-Host "Configuration JEA 'PatchManagementJEA' enregistrée avec succès." -ForegroundColor Green
    }
}