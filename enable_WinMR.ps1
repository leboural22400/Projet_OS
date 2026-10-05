# 1. Autoriser l'exécution de scripts locaux sur votre machine
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# 2. Ajouter les IP de vos VMs aux hôtes de confiance (TrustedHosts) de WinRM
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
# (Dans un vrai réseau, remplacez "*" par les IP spécifiques, ex: "192.168.1.11,192.168.1.12")

# Au début du script, demandez les identifiants administrateur des postes cibles :
$Cred = Get-Credential "Administrateur"

# Puis modifiez vos Invoke-Command pour les utiliser :
Invoke-Command -ComputerName $IP -Credential $Cred -ScriptBlock { ... }
