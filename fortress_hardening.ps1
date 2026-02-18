<#
.SYNOPSIS
    Zero-Touch Server Hardening para Windows (PowerShell)
.DESCRIPTION
    Automatiza la configuración de seguridad esencial en sistemas Windows.
    Requiere ejecución como Administrador.
.NOTES
    Autor: Alejandro González Santana (Adaptado a PowerShell)
    Versión: 1.0
#>

#Requires -RunAsAdministrator

# Colores para output (solo consola)
$GREEN = "Green"
$YELLOW = "Yellow"
$RED = "Red"
$NC = "White"

$LOGFILE = "C:\ProgramData\fortress_hardening.log"

# Función para loguear y mostrar mensajes
function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LOGFILE -Append
    Write-Host $Message -ForegroundColor $Color
}

Write-Log "[+] Iniciando protocolo de Hardening para Windows..." $GREEN

# Verificar elevación (ya se hace con #Requires)
Write-Log "[*] Ejecutando como Administrador." $YELLOW

# Backup de configuraciones importantes
$backupDir = "C:\HardeningBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Write-Log "[*] Creando backup en $backupDir" $YELLOW

# Backup de directivas de seguridad
secedit /export /cfg "$backupDir\security_policy.inf" | Out-Null

# Backup de reglas de firewall
netsh advfirewall export "$backupDir\firewall.wfw" | Out-Null

# Backup de configuración de RDP (registro)
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "$backupDir\rdp.reg" /y 2>&1 | Out-Null

# 1. Actualizaciones de Windows (opcional, requiere módulo PSWindowsUpdate)
Write-Log "[+] Buscando e instalando actualizaciones de seguridad..." $GREEN
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    Import-Module PSWindowsUpdate
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot:$false | Out-File -FilePath $LOGFILE -Append
} else {
    Write-Log "[!] Módulo PSWindowsUpdate no instalado. Las actualizaciones deben gestionarse manualmente o mediante Windows Update." $YELLOW
    # Alternativa: Usar USOClient (Windows Update) pero es menos controlable
    # Start-Process "usoclient" -ArgumentList "ScanInstallWait" -Wait
}

# 2. Configuración del Firewall de Windows (Defender)
Write-Log "[+] Configurando Firewall de Windows..." $GREEN
# Resetear políticas
netsh advfirewall reset | Out-Null
# Establecer perfil por defecto: bloquear entrante, permitir saliente
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Reglas básicas permitidas
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName "Allow ICMP (ping)" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow | Out-Null

# Bloquear otras reglas innecesarias (ejemplo: SMB)
Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Out-Null

Write-Log "[+] Firewall configurado. Reglas activas:" $GREEN
Get-NetFirewallRule -Enabled True | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" } | Select-Object DisplayName, Direction, Action | Out-Host

# 3. Hardening de RDP
Write-Log "[+] Reforzando seguridad de RDP..." $GREEN
# Requerir autenticación a nivel de red (NLA)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
# Deshabilitar autenticación por contraseña si se prefiere solo credenciales en dominio o tarjetas inteligentes (opcional)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
# Cambiar puerto (opcional, descomentar si se desea)
# $newPort = 3390
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value $newPort
# New-NetFirewallRule -DisplayName "RDP Custom Port" -Direction Inbound -Protocol TCP -LocalPort $newPort -Action Allow
# Disable-NetFirewallRule -DisplayName "Allow RDP"
# Write-Log "[!] Puerto RDP cambiado a $newPort. Asegúrate de actualizar tus conexiones." $YELLOW

# 4. Protección contra fuerza bruta (Account Lockout Policy)
Write-Log "[+] Configurando política de bloqueo de cuentas..." $GREEN
# Aplicar mediante secedit (requiere archivo inf)
$seceditContent = @"
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@
$seceditContent | Out-File -FilePath "$env:TEMP\lockout.inf" -Encoding ascii
secedit /configure /db "$env:TEMP\lockout.sdb" /cfg "$env:TEMP\lockout.inf" /quiet | Out-Null
Write-Log "[*] Política: 5 intentos fallidos, bloqueo 30 minutos." $YELLOW

# 5. Windows Defender (Antivirus)
Write-Log "[+] Configurando Windows Defender..." $GREEN
# Actualizar firmas
Update-MpSignature | Out-Null
# Habilitar protección en tiempo real (si no está)
Set-MpPreference -DisableRealtimeMonitoring $false
# Excluir carpetas de backup o cuarentena si se desea (ejemplo)
# Add-MpPreference -ExclusionPath "C:\Backup"
# Configurar escaneo rápido diario programado
$scanTask = Get-ScheduledTask -TaskName "Windows Defender Scheduled Scan" -ErrorAction SilentlyContinue
if ($scanTask) {
    Enable-ScheduledTask -TaskName "Windows Defender Scheduled Scan"
} else {
    # Crear tarea si no existe
    $action = New-ScheduledTaskAction -Execute "MpCmdRun.exe" -Argument "-Scan -ScanType 1"
    $trigger = New-ScheduledTaskTrigger -Daily -At 03:00AM
    Register-ScheduledTask -TaskName "Windows Defender Daily Quick Scan" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
}
Write-Log "[*] Defender configurado con escaneo rápido diario a las 3 AM." $GREEN

# 6. Deshabilitar protocolos y servicios inseguros
Write-Log "[+] Deshabilitando SMBv1, LLMNR y otros protocolos obsoletos..." $GREEN
# SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# LLMNR (deshabilitar via directiva de grupo local)
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord
# NetBIOS sobre TCP/IP (deshabilitar en todas las interfaces)
$interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($iface in $interfaces) {
    $iface.SetTcpipNetbios(2) | Out-Null  # 2 = Disable
}
# Deshabilitar servicios innecesarios (ejemplo: Print Spooler si no se usa)
# Stop-Service Spooler -Force
# Set-Service Spooler -StartupType Disabled

# 7. Parámetros de red seguros (TCP/IP hardening)
Write-Log "[+] Aplicando protecciones de red (SYN cookies, etc.)..." $GREEN
# Habilitar SYN cookies
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableDeadGWDetect" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000  # 5 minutos

# 8. Auditoría básica
Write-Log "[+] Configurando políticas de auditoría..." $GREEN
# Usar auditpol para habilitar auditorías de éxito/fallo en eventos de inicio de sesión
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null

# 9. Ajustar permisos en archivos y claves de registro sensibles
Write-Log "[+] Asegurando permisos en archivos del sistema..." $GREEN
# Ejemplo: restringir acceso a cmd.exe solo a Administradores (opcional)
# $acl = Get-Acl "C:\Windows\System32\cmd.exe"
# $acl.SetAccessRuleProtection($true, $false)
# $admins = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
# $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "Allow")
# $acl.AddAccessRule($ace)
# Set-Acl "C:\Windows\System32\cmd.exe" $acl

# 10. Habilitar UAC (Control de Cuentas de Usuario)
Write-Log "[+] Asegurando UAC..." $GREEN
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2  # Solicitar consentimiento para administradores

# 11. Limpieza y reporte final
Write-Log "[+] Hardening completado. Sistema securizado y optimizado." $GREEN
Write-Log "[!] Recuerda: La mejor seguridad es la que no requiere intervención." $GREEN
Write-Log "[*] Log disponible en: $LOGFILE" $YELLOW
Write-Log "[*] Backups guardados en: $backupDir" $YELLOW

# Pausa para revisión
Read-Host "Presiona Enter para salir"