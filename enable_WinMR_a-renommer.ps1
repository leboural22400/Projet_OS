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

    [Parameter(Mandatory=$false, HelpMessage="Désactive le filtrage UAC distant pour les comptes administrateurs locaux (Workgroup uniquement).")]
    [switch]$AllowLocalAdmins,

    [Parameter(Mandatory=$false, HelpMessage="Active le point de terminaison JEA (Partie 7.7).")]
    [switch]$RegisterJEA
)

$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"
$ComputersExample = "$ScriptPath\computers.example.txt"

# Initialisation automatique de computers.txt depuis l'exemple s'il n'existe pas encore
if (-not (Test-Path $ComputersFile) -and (Test-Path $ComputersExample)) {
    Copy-Item -Path $ComputersExample -Destination $ComputersFile
}

# Autoriser l'exécution de scripts locaux
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

if ($Role -eq "Admin") {
    Write-Host "=== CONFIGURATION DU POSTE D'ADMINISTRATION ===" -ForegroundColor Cyan

    Start-Service -Name WinRM
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    # Restriction de TrustedHosts uniquement aux IP valides présentes dans computers.txt (Parties 7.1 & 7.5)
    if (Test-Path $ComputersFile) {
        $AllowedIPs = @(Get-Content $ComputersFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ';' } | ForEach-Object {
            ($_ -split ';', 2)[1].Trim()
        } | Where-Object { $_ -ne "" }) -join ","

        if ($AllowedIPs -ne "") {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $AllowedIPs -Force
            Write-Host "TrustedHosts restreint aux adresses IP du parc : $AllowedIPs" -ForegroundColor Green
        } else {
            Write-Warning "Aucune adresse IP valide trouvée dans computers.txt."
        }
    } else {
        Write-Warning "Fichier computers.txt introuvable dans $ScriptPath."
    }
}

if ($Role -eq "Cible") {
    Write-Host "=== CONFIGURATION DU POSTE CIBLE SUPERVISE ===" -ForegroundColor Cyan

    # 1. Activation de PowerShell Remoting même sur un profil réseau Public (Partie 1.4)
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    # 2. Autoriser le Ping ICMP entrant sur tous les profils (Partie 1.1 & 2.1)
    $IcmpRules = Get-NetFirewallRule -Name "FPS-ICMP4-ERQ-In*" -ErrorAction SilentlyContinue
    if ($IcmpRules) {
        $IcmpRules | Enable-NetFirewallRule
        Write-Host "`n--- Règles pare-feu ICMPv4 Echo Request activées ---" -ForegroundColor Yellow
        $IcmpRules | ForEach-Object {
            [PSCustomObject]@{
                Regle  = $_.Name
                Profil = $_.Profile
                Active = $_.Enabled
            }
        } | Format-Table -AutoSize
    } else {
        Write-Warning "Aucune règle pare-feu FPS-ICMP4-ERQ-In* trouvée."
    }

    # 3. Restreindre toutes les règles pare-feu WinRM (y compris PUBLIC sur Windows 10/11) à l'IP Admin (Partie 7.5)
    $WinRMRules = Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP*" -ErrorAction SilentlyContinue
    if ($WinRMRules) {
        if ($AdminIP -ne "Any" -and $AdminIP -ne "") {
            $WinRMRules | Set-NetFirewallRule -RemoteAddress $AdminIP
        }
        Write-Host "--- Partie 7.5 : Vérification des règles pare-feu WinRM ---" -ForegroundColor Yellow
        $WinRMRules | ForEach-Object {
            [PSCustomObject]@{
                Regle   = $_.Name
                Profil  = $_.Profile
                Active  = $_.Enabled
                Sources = (($_ | Get-NetFirewallAddressFilter).RemoteAddress) -join ", "
            }
        } | Format-Table -AutoSize
    } else {
        Write-Warning "Aucune règle pare-feu WINRM-HTTP-In-TCP* trouvée."
    }

    # 4. Optionnel : Désactiver le filtrage UAC distant pour les administrateurs locaux autres que "Administrateur"
    if ($AllowLocalAdmins) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                         -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Warning "LocalAccountTokenFilterPolicy = 1 appliqué (compromis de laboratoire en Workgroup)."
    }

    # 5. Vérification des utilisateurs autorisés à ouvrir une session distante (Partie 7.2)
    Write-Host "--- Partie 7.2 : Permissions des sessions distantes (PSSessionConfiguration) ---" -ForegroundColor Yellow
    Get-PSSessionConfiguration | Select-Object Name, Permission | Format-List

    Write-Host "--- Partie 7.2 : Membres du groupe 'Utilisateurs de gestion à distance' (SID S-1-5-32-580) ---" -ForegroundColor Yellow
    $RMGroup = Get-LocalGroup -SID "S-1-5-32-580"
    Get-LocalGroupMember -Group $RMGroup | Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

    # 6. Enregistrement optionnel du profil JEA de moindre privilège (Parties 7.3 & 7.7)
    if ($RegisterJEA) {
        $JeaFile = "$ScriptPath\PatchManagementJEA.pssc"
        if (Test-Path $JeaFile) {
            if (Get-PSSessionConfiguration -Name "PatchManagementJEA" -ErrorAction SilentlyContinue) {
                Unregister-PSSessionConfiguration -Name "PatchManagementJEA" -Force
            }
            Register-PSSessionConfiguration -Name "PatchManagementJEA" -Path $JeaFile -Force
            Restart-Service WinRM
            Write-Host "Configuration JEA 'PatchManagementJEA' enregistrée avec succès." -ForegroundColor Green
        } else {
            Write-Warning "Option -RegisterJEA ignorée : le fichier $JeaFile est introuvable."
        }
    }
}