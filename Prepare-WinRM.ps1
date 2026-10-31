#Requires -RunAsAdministrator
# ==============================================================================
# PROJET : SYSTEME DE GESTION DES MISES A JOUR EN POWERSHELL
# SCRIPT : Préparation de l'environnement et sécurisation WinRM (Parties 1 & 7)
# Auteur : Martin Bourreau
#
# Usage :
#   Sur chaque poste supervisé :  .\Prepare-WinRM.ps1 -Role Cible -AdminIP 192.168.10.1 [-RegisterJEA -JeaMember svc-patch] [-AllowLocalAdmins]
#   Sur le poste d'administration : .\Prepare-WinRM.ps1 -Role Admin
# ==============================================================================

param(
    [Parameter(Mandatory = $true, HelpMessage = "Indiquez 'Admin' sur le poste central ou 'Cible' sur les postes supervisés.")]
    [ValidateSet("Admin", "Cible")]
    [string]$Role,

    [Parameter(Mandatory = $false, HelpMessage = "Adresse IP du poste d'administration (filtrage du pare-feu WinRM sur la cible).")]
    [string]$AdminIP = "Any",

    [Parameter(Mandatory = $false, HelpMessage = "Désactive le filtrage UAC distant pour les administrateurs locaux (Workgroup, laboratoire uniquement).")]
    [switch]$AllowLocalAdmins,

    [Parameter(Mandatory = $false, HelpMessage = "Crée et enregistre le point de terminaison JEA PatchManagementJEA (Parties 7.3 & 7.7).")]
    [switch]$RegisterJEA,

    [Parameter(Mandatory = $false, HelpMessage = "Compte local à ajouter au groupe PatchAuditors autorisé sur l'endpoint JEA (ex : svc-patch).")]
    [string]$JeaMember = ""
)

$ScriptPath = $PSScriptRoot
$ComputersFile = "$ScriptPath\computers.txt"
$ComputersExample = "$ScriptPath\computers.example.txt"

# Initialisation de computers.txt depuis l'exemple s'il n'existe pas encore
if (-not (Test-Path $ComputersFile) -and (Test-Path $ComputersExample)) {
    Copy-Item -Path $ComputersExample -Destination $ComputersFile
}

# Autoriser l'exécution de scripts locaux
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# ==============================================================================
# ROLE ADMIN : poste d'administration centralisé
# ==============================================================================
if ($Role -eq "Admin") {
    Write-Host "=== CONFIGURATION DU POSTE D'ADMINISTRATION ===" -ForegroundColor Cyan

    # Démarrage du service WinRM (nécessaire côté client pour TrustedHosts)
    Start-Service -Name WinRM
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    if (Test-Path $ComputersFile) {
        # Lecture de computers.txt (commentaires et lignes mal formées ignorés)
        $Parc = @(Get-Content $ComputersFile | Where-Object { $_ -notmatch '^\s*#' -and $_ -match ';' } | ForEach-Object {
            $parts = $_ -split ';', 2
            if ($parts[0].Trim() -ne "" -and $parts[1].Trim() -ne "") {
                [PSCustomObject]@{ Nom = $parts[0].Trim(); IP = $parts[1].Trim() }
            }
        })

        # Restriction de TrustedHosts aux seules IP du parc (Parties 7.1 & 7.5)
        $AllowedIPs = ($Parc.IP | Select-Object -Unique) -join ","
        if ($AllowedIPs -ne "") {
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $AllowedIPs -Force
            Write-Host "TrustedHosts restreint aux adresses IP du parc : $AllowedIPs" -ForegroundColor Green
        } else {
            Write-Warning "Aucune adresse IP valide trouvée dans computers.txt."
        }

        # Partie 7.6 : méthodes d'authentification AUTORISÉES côté client
        # (indique ce qui est permis, pas ce qui est réellement négocié : voir README)
        Write-Host "`n--- Partie 7.6 : Méthodes d'authentification WinRM autorisées (client) ---" -ForegroundColor Yellow
        Get-ChildItem WSMan:\localhost\Client\Auth | Select-Object Name, Value | Format-Table -AutoSize

        # Parties 1.1, 1.3 & 1.4 : nom, IP et état de disponibilité de chaque poste
        Write-Host "--- Parties 1.1, 1.3 & 1.4 : Disponibilité des postes du parc ---" -ForegroundColor Yellow
        $Parc | ForEach-Object {
            $Ping  = Test-Connection -ComputerName $_.IP -Count 1 -Quiet
            $Wsman = [bool](Test-WSMan -ComputerName $_.IP -ErrorAction SilentlyContinue)
            [PSCustomObject]@{
                Nom           = $_.Nom
                Adresse_IP    = $_.IP
                Ping_ICMP     = if ($Ping)  { "OK" } else { "KO" }
                WinRM_WSMan   = if ($Wsman) { "OK" } else { "KO" }
                Disponibilite = if ($Ping -or $Wsman) { "Accessible" } else { "Inaccessible" }
            }
        } | Format-Table -AutoSize
    } else {
        Write-Warning "Fichier computers.txt introuvable dans $ScriptPath."
    }
}

# ==============================================================================
# ROLE CIBLE : poste supervisé
# ==============================================================================
if ($Role -eq "Cible") {
    Write-Host "=== CONFIGURATION DU POSTE CIBLE SUPERVISE ===" -ForegroundColor Cyan

    # 1. Activation de PowerShell Remoting, même sur un profil réseau Public (Partie 1.4)
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    $WinRMService = Get-Service -Name WinRM
    Write-Host "État du service WinRM : $($WinRMService.Status)" -ForegroundColor Green

    # 2. Ping ICMPv4 entrant sur tous les profils (Parties 1.1 & 2.1)
    $IcmpRules = Get-NetFirewallRule -Name "FPS-ICMP4-ERQ-In*" -ErrorAction SilentlyContinue
    if ($IcmpRules) {
        $IcmpRules | Enable-NetFirewallRule
        Write-Host "`n--- Règles pare-feu ICMPv4 Echo Request ---" -ForegroundColor Yellow
        Get-NetFirewallRule -Name "FPS-ICMP4-ERQ-In*" | ForEach-Object {
            [PSCustomObject]@{ Regle = $_.Name; Profil = $_.Profile; Active = $_.Enabled }
        } | Format-Table -AutoSize
    } else {
        Write-Warning "Aucune règle pare-feu FPS-ICMP4-ERQ-In* trouvée."
    }

    # 3. Restriction de TOUTES les règles WinRM (y compris -PUBLIC sur Windows 10/11) à l'IP admin (Partie 7.5)
    $WinRMRules = Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP*" -ErrorAction SilentlyContinue
    if ($WinRMRules) {
        if ($AdminIP -ne "Any" -and $AdminIP -ne "") {
            $WinRMRules | Set-NetFirewallRule -RemoteAddress $AdminIP
        } else {
            Write-Warning "Aucune -AdminIP fournie : les règles WinRM ne sont pas restreintes."
        }
        Write-Host "--- Partie 7.5 : Règles pare-feu WinRM (port 5985) ---" -ForegroundColor Yellow
        Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP*" | ForEach-Object {
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

    # 4. Optionnel : désactivation du filtrage UAC distant (compromis de laboratoire en Workgroup)
    if ($AllowLocalAdmins) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                         -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Warning "LocalAccountTokenFilterPolicy = 1 appliqué (compromis de laboratoire, à éviter en production)."
    }

    # 5. Partie 7.2 : qui peut ouvrir une session distante ?
    Write-Host "--- Partie 7.2 : Permissions des points de terminaison PowerShell ---" -ForegroundColor Yellow
    Get-PSSessionConfiguration | Select-Object Name, Permission | Format-List

    Write-Host "--- Partie 7.2 : Membres du groupe 'Utilisateurs de gestion à distance' (S-1-5-32-580) ---" -ForegroundColor Yellow
    $RMGroup = Get-LocalGroup -SID "S-1-5-32-580"
    Get-LocalGroupMember -Group $RMGroup | Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

    # 6. Partie 7.6 : méthodes d'authentification acceptées par le service WinRM
    Write-Host "--- Partie 7.6 : Méthodes d'authentification WinRM acceptées (service) ---" -ForegroundColor Yellow
    Get-ChildItem WSMan:\localhost\Service\Auth | Select-Object Name, Value | Format-Table -AutoSize

    # 7. Point de terminaison JEA de moindre privilège (Parties 7.3 & 7.7)
    if ($RegisterJEA) {
        $ModuleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PatchManagementJEA"
        $RoleDir   = "$ModuleDir\RoleCapabilities"
        $RoleFile  = "$RoleDir\PatchManagementRole.psrc"
        $JeaFile   = "$ScriptPath\PatchManagementJEA.pssc"
        $JeaGroup  = "PatchAuditors"

        # Groupe dédié. On n'utilise PAS "Utilisateurs de gestion à distance" :
        # ce groupe ouvre aussi l'endpoint complet Microsoft.PowerShell, ce qui contournerait JEA.
        if (-not (Get-LocalGroup -Name $JeaGroup -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $JeaGroup -Description "Accès à l'endpoint JEA PatchManagementJEA" | Out-Null
        }
        if ($JeaMember -ne "") {
            if (-not (Get-LocalGroupMember -Group $JeaGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\$JeaMember" })) {
                Add-LocalGroupMember -Group $JeaGroup -Member $JeaMember
            }
        }

        # Régénération systématique pour que le rôle reflète toujours ce script
        Remove-Item -Path $RoleFile, $JeaFile -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $RoleDir -Force | Out-Null
        New-ModuleManifest -Path "$ModuleDir\PatchManagementJEA.psd1"

        # Liste blanche stricte : seules les commandes et paramètres utilisés par l'audit sont visibles.
        # Les modules sont importés explicitement : l'auto-chargement est désactivé dans une session JEA.
        New-PSRoleCapabilityFile -Path $RoleFile -ModulesToImport 'CimCmdlets', 'Microsoft.PowerShell.Management' -VisibleCmdlets @(
            'Get-HotFix',
            @{ Name = 'Get-Service';     Parameters = @{ Name = 'Name'; ValidateSet = 'wuauserv' } },
            @{ Name = 'Get-CimInstance'; Parameters = @{ Name = 'ClassName'; ValidateSet = 'Win32_OperatingSystem', 'Win32_ComputerSystem', 'Win32_BIOS', 'Win32_LogicalDisk' } }
        )

        # Session restreinte (NoLanguage) exécutée sous un compte virtuel temporaire
        New-PSSessionConfigurationFile -Path $JeaFile -SessionType RestrictedRemoteServer -RunAsVirtualAccount `
            -RoleDefinitions @{ "$env:COMPUTERNAME\$JeaGroup" = @{ RoleCapabilities = 'PatchManagementRole' } }

        if (-not (Test-PSSessionConfigurationFile -Path $JeaFile)) {
            Write-Warning "Fichier JEA invalide : enregistrement annulé."
        } else {
            if (Get-PSSessionConfiguration -Name "PatchManagementJEA" -ErrorAction SilentlyContinue) {
                Unregister-PSSessionConfiguration -Name "PatchManagementJEA" -Force
            }
            # -Force redémarre WinRM automatiquement
            Register-PSSessionConfiguration -Name "PatchManagementJEA" -Path $JeaFile -Force | Out-Null
            Write-Host "Endpoint JEA 'PatchManagementJEA' enregistré pour le groupe $JeaGroup." -ForegroundColor Green

            Write-Host "--- Partie 7.7 : Membres autorisés sur l'endpoint JEA ---" -ForegroundColor Yellow
            Get-LocalGroupMember -Group $JeaGroup | Select-Object Name, PrincipalSource | Format-Table -AutoSize
        }
    }
}
