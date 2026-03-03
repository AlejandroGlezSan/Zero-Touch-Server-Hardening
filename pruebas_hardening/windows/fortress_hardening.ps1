<#
.SYNOPSIS
    Zero-Touch Server Hardening para Windows (PowerShell) v3.0
.DESCRIPTION
    Automatiza la configuración de seguridad esencial en sistemas Windows.
    Incluye idempotencia y reversión automática en caso de error crítico.
    Requiere ejecución como Administrador.

    Mejoras v3.0:
      - Modo -DryRun: previsualiza cambios sin aplicarlos
      - Hardening de protocolos criptográficos TLS/SCHANNEL (equivalente SSH ciphers)
      - Gestión de usuarios privilegiados: auditoría de admins locales + política de auditoría extendida
.NOTES
    Autor: Alejandro González Santana
    Versión: 3.0
#>

#Requires -RunAsAdministrator

param(
    [switch]$DryRun
)

# ─────────────────────────────────────────────
# Configuración inicial
# ─────────────────────────────────────────────
$GREEN  = "Green"
$YELLOW = "Yellow"
$RED    = "Red"
$CYAN   = "Cyan"

$LOGFILE       = "C:\ProgramData\fortress_hardening.log"
$ROLLBACK_NEEDED = $false

# ─────────────────────────────────────────────
# Funciones base
# ─────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LOGFILE -Append
    Write-Host $Message -ForegroundColor $Color
}

# Ejecuta un bloque de código o muestra qué haría en DryRun
function Invoke-Step {
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    if ($DryRun) {
        Write-Log "[DRY-RUN] Ejecutaría: $Description" $CYAN
    } else {
        try {
            & $Action
        } catch {
            Write-Log "[!] Error en paso '$Description': $_" $RED
            throw
        }
    }
}

function Invoke-Rollback {
    Write-Log "[!] ¡Error crítico! Iniciando reversión desde backup..." $RED
    if (Test-Path $backupDir) {
        secedit /configure /db "$env:TEMP\rollback.sdb" /cfg "$backupDir\security_policy.inf" /quiet 2>&1 | Out-Null
        netsh advfirewall import "$backupDir\firewall.wfw" | Out-Null
        reg import "$backupDir\rdp.reg" 2>&1 | Out-Null
        Write-Log "[+] Reversión completada. Revise el sistema manualmente." $YELLOW
    } else {
        Write-Log "[!] No se encontró backup. No se puede revertir." $RED
    }
    exit 1
}

$ErrorActionPreference = "Stop"
trap {
    Write-Log "[!] Error inesperado: $_" $RED
    if ($ROLLBACK_NEEDED) { Invoke-Rollback }
    exit 1
}

# ─────────────────────────────────────────────
# Inicio
# ─────────────────────────────────────────────
if ($DryRun) {
    Write-Log "╔══════════════════════════════════════════════════╗" $CYAN
    Write-Log "║         MODO DRY-RUN: sin cambios reales         ║" $CYAN
    Write-Log "╚══════════════════════════════════════════════════╝" $CYAN
}

Write-Log "[+] Iniciando protocolo de Hardening para Windows (v3.0)..." $GREEN
Write-Log "[*] Ejecutando como Administrador." $YELLOW

# ─────────────────────────────────────────────
# Backup de configuraciones
# ─────────────────────────────────────────────
$backupDir = "C:\HardeningBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

if ($DryRun) {
    Write-Log "[DRY-RUN] Crearía backup en $backupDir (policy, firewall, RDP, SCHANNEL)" $CYAN
} else {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-Log "[*] Creando backup en $backupDir" $YELLOW
    secedit /export /cfg "$backupDir\security_policy.inf" | Out-Null
    netsh advfirewall export "$backupDir\firewall.wfw" | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "$backupDir\rdp.reg" /y 2>&1 | Out-Null
    # Backup de claves SCHANNEL
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "$backupDir\schannel.reg" /y 2>&1 | Out-Null
}

$ROLLBACK_NEEDED = $true

# ─────────────────────────────────────────────
# 1. Actualizaciones de Windows
# ─────────────────────────────────────────────
Write-Log "[+] Buscando e instalando actualizaciones de seguridad..." $GREEN
Invoke-Step "Instalar actualizaciones via PSWindowsUpdate" {
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Import-Module PSWindowsUpdate
        $updates = Get-WUList
        if ($updates) {
            Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot:$false | Out-File -FilePath $LOGFILE -Append
        } else {
            Write-Log "[*] No hay actualizaciones pendientes." $YELLOW
        }
    } else {
        Write-Log "[!] PSWindowsUpdate no instalado. Gestión manual requerida." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 2. Firewall de Windows
# ─────────────────────────────────────────────
Write-Log "[+] Configurando Firewall de Windows..." $GREEN

Invoke-Step "Configurar perfiles de firewall a Block/Allow" {
    $currentProfile = Get-NetFirewallProfile -Profile Domain | Select-Object -ExpandProperty DefaultInboundAction
    if ($currentProfile -ne "Block") {
        netsh advfirewall reset | Out-Null
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        Write-Log "[*] Perfiles configurados a Block/Allow." $GREEN
    } else {
        Write-Log "[*] Firewall ya configurado correctamente." $YELLOW
    }
}

$rules = @(
    @{Name="Allow RDP"; Port=3389},
    @{Name="Allow HTTP"; Port=80},
    @{Name="Allow HTTPS"; Port=443}
)

foreach ($rule in $rules) {
    Invoke-Step "Añadir regla firewall: $($rule.Name)" {
        if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol TCP -LocalPort $rule.Port -Action Allow | Out-Null
            Write-Log "[*] Regla $($rule.Name) añadida." $GREEN
        } else {
            Write-Log "[*] Regla $($rule.Name) ya existe." $YELLOW
        }
    }
}

Invoke-Step "Añadir regla ICMP" {
    if (-not (Get-NetFirewallRule -DisplayName "Allow ICMP (ping)" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow ICMP (ping)" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow | Out-Null
    } else {
        Write-Log "[*] Regla ICMP ya existe." $YELLOW
    }
}

Invoke-Step "Deshabilitar regla SMB entrante" {
    $smbRule = Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -ErrorAction SilentlyContinue |
               Where-Object { $_.Enabled -eq $true }
    if ($smbRule) {
        Disable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Out-Null
        Write-Log "[*] Regla SMB deshabilitada." $GREEN
    } else {
        Write-Log "[*] Regla SMB ya está deshabilitada." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 3. Hardening de RDP
# ─────────────────────────────────────────────
Write-Log "[+] Reforzando seguridad de RDP..." $GREEN
Invoke-Step "Activar NLA en RDP" {
    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
           -Name "UserAuthentication" -ErrorAction SilentlyContinue
    if ($nla.UserAuthentication -ne 1) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                         -Name "UserAuthentication" -Value 1
        Write-Log "[*] NLA activada." $GREEN
    } else {
        Write-Log "[*] NLA ya está activada." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 4. Política de bloqueo de cuentas
# ─────────────────────────────────────────────
Write-Log "[+] Configurando política de bloqueo de cuentas..." $GREEN
Invoke-Step "Aplicar política: 5 intentos, bloqueo 30 min" {
    $currentLockout = net accounts | Select-String "Lockout threshold"
    if ($currentLockout -notmatch "5") {
        $seceditContent = @"
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@
        $seceditContent | Out-File -FilePath "$env:TEMP\lockout.inf" -Encoding ascii
        secedit /configure /db "$env:TEMP\lockout.sdb" /cfg "$env:TEMP\lockout.inf" /quiet | Out-Null
        Write-Log "[*] Política aplicada: 5 intentos, bloqueo 30 min." $GREEN
    } else {
        Write-Log "[*] Política ya configurada." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 5. Windows Defender
# ─────────────────────────────────────────────
Write-Log "[+] Configurando Windows Defender..." $GREEN
Invoke-Step "Actualizar firmas de Defender" { Update-MpSignature | Out-Null }

Invoke-Step "Activar protección en tiempo real" {
    $realtime = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring
    if ($realtime -eq $true) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Log "[*] Protección en tiempo real activada." $GREEN
    } else {
        Write-Log "[*] Protección en tiempo real ya activa." $YELLOW
    }
}

Invoke-Step "Programar escaneo rápido diario" {
    $taskName = "Windows Defender Daily Quick Scan"
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        $action  = New-ScheduledTaskAction -Execute "MpCmdRun.exe" -Argument "-Scan -ScanType 1"
        $trigger = New-ScheduledTaskTrigger -Daily -At 03:00AM
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest | Out-Null
        Write-Log "[*] Tarea de escaneo programada." $GREEN
    } else {
        Write-Log "[*] Tarea de escaneo ya existe." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 6. Deshabilitar protocolos inseguros
# ─────────────────────────────────────────────
Write-Log "[+] Deshabilitando SMBv1, LLMNR y NetBIOS..." $GREEN

Invoke-Step "Deshabilitar SMBv1" {
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $true) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Log "[*] SMBv1 deshabilitado." $GREEN
    } else {
        Write-Log "[*] SMBv1 ya deshabilitado." $YELLOW
    }
}

Invoke-Step "Deshabilitar LLMNR" {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    $llmnr = Get-ItemProperty -Path $regPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($llmnr.EnableMulticast -ne 0) {
        Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord
        Write-Log "[*] LLMNR deshabilitado." $GREEN
    } else {
        Write-Log "[*] LLMNR ya deshabilitado." $YELLOW
    }
}

Invoke-Step "Deshabilitar NetBIOS en todas las interfaces" {
    $interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($iface in $interfaces) {
        if ($iface.TcpipNetbiosOptions -ne 2) {
            $iface.SetTcpipNetbios(2) | Out-Null
            Write-Log "[*] NetBIOS deshabilitado en $($iface.Description)." $GREEN
        } else {
            Write-Log "[*] NetBIOS ya deshabilitado en $($iface.Description)." $YELLOW
        }
    }
}

# ─────────────────────────────────────────────
# 7. Hardening de red TCP/IP
# ─────────────────────────────────────────────
Write-Log "[+] Aplicando protecciones de red TCP/IP..." $GREEN
$tcpParams = @{
    "SynAttackProtect"    = 1
    "EnableICMPRedirect"  = 0
    "DisableIPSourceRouting" = 2
    "EnableDeadGWDetect"  = 0
    "KeepAliveTime"       = 300000
}
foreach ($key in $tcpParams.Keys) {
    Invoke-Step "Configurar $key = $($tcpParams[$key])" {
        $current = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                   -Name $key -ErrorAction SilentlyContinue
        if ($current.$key -ne $tcpParams[$key]) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
                             -Name $key -Value $tcpParams[$key]
            Write-Log "[*] $key = $($tcpParams[$key])." $GREEN
        } else {
            Write-Log "[*] $key ya correcto." $YELLOW
        }
    }
}

# ─────────────────────────────────────────────
# 8. Hardening de protocolos TLS/SCHANNEL (NUEVO v3.0)
#    Equivalente al hardening de cifrados SSH en Linux.
#    Deshabilita TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0 y cifrados débiles.
#    Habilita TLS 1.2 y TLS 1.3.
# ─────────────────────────────────────────────
Write-Log "[+] Aplicando hardening de protocolos TLS/SCHANNEL..." $GREEN

$schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Protocolos a deshabilitar
$disableProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $disableProtocols) {
    Invoke-Step "Deshabilitar $proto (Client y Server)" {
        foreach ($role in @("Client", "Server")) {
            $path = "$schannelBase\Protocols\$proto\$role"
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "Enabled"            -Value 0 -Type DWord
            Set-ItemProperty -Path $path -Name "DisabledByDefault"  -Value 1 -Type DWord
            Write-Log "[*] $proto ($role) deshabilitado." $GREEN
        }
    }
}

# Protocolos a habilitar
$enableProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($proto in $enableProtocols) {
    Invoke-Step "Habilitar $proto (Client y Server)" {
        foreach ($role in @("Client", "Server")) {
            $path = "$schannelBase\Protocols\$proto\$role"
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "Enabled"           -Value 1 -Type DWord
            Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWord
            Write-Log "[*] $proto ($role) habilitado." $GREEN
        }
    }
}

# Cifrados débiles: deshabilitar RC4, DES, 3DES, NULL
$weakCiphers = @("RC4 128/128", "RC4 64/64", "RC4 56/56", "RC4 40/128",
                 "DES 56/56", "Triple DES 168", "NULL")
foreach ($cipher in $weakCiphers) {
    Invoke-Step "Deshabilitar cifrado débil: $cipher" {
        $path = "$schannelBase\Ciphers\$cipher"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
        Write-Log "[*] Cifrado $cipher deshabilitado." $GREEN
    }
}

# Hashes débiles: deshabilitar MD5 y SHA-1 en SCHANNEL
$weakHashes = @("MD5", "SHA")
foreach ($hash in $weakHashes) {
    Invoke-Step "Deshabilitar hash débil: $hash" {
        $path = "$schannelBase\Hashes\$hash"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
        Write-Log "[*] Hash $hash deshabilitado." $GREEN
    }
}

# Orden de suites de cifrado TLS modernas (solo AES-GCM y ChaCha20 donde aplique)
Invoke-Step "Configurar orden de cipher suites TLS modernas" {
    $modernSuites = @(
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    )
    $suiteString = $modernSuites -join ","
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "Functions" -Value $suiteString
    Write-Log "[*] Cipher suites TLS configuradas a algoritmos modernos." $GREEN
}

Write-Log "[+] Hardening TLS/SCHANNEL completado." $GREEN

# ─────────────────────────────────────────────
# 9. Auditoría básica
# ─────────────────────────────────────────────
Write-Log "[+] Configurando políticas de auditoría..." $GREEN
$auditCategories = @("Logon", "Account Logon", "Security Group Management")
foreach ($cat in $auditCategories) {
    Invoke-Step "Activar auditoría para: $cat" {
        auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
        Write-Log "[*] Auditoría activada para $cat." $GREEN
    }
}

# ─────────────────────────────────────────────
# 10. UAC
# ─────────────────────────────────────────────
Write-Log "[+] Asegurando UAC..." $GREEN
Invoke-Step "Activar UAC con nivel de consentimiento admin" {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uac = Get-ItemProperty -Path $uacPath -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -ne 1) {
        Set-ItemProperty -Path $uacPath -Name "EnableLUA"                    -Value 1
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin"   -Value 2
        Write-Log "[*] UAC activado." $GREEN
    } else {
        Write-Log "[*] UAC ya activado." $YELLOW
    }
}

# ─────────────────────────────────────────────
# 11. Gestión de usuarios privilegiados (NUEVO v3.0)
#     - Informe de administradores locales
#     - Auditoría extendida de uso de privilegios
#     - Desactivación de la cuenta Administrator por defecto
# ─────────────────────────────────────────────
Write-Log "[+] Auditando usuarios con privilegios de administrador..." $GREEN

Invoke-Step "Listar miembros del grupo Administrators" {
    Write-Log "[*] Miembros actuales del grupo Administrators:" $YELLOW
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    foreach ($admin in $admins) {
        Write-Log "    - $($admin.Name) [$($admin.PrincipalSource)]" $YELLOW
        "$($admin.Name) [$($admin.PrincipalSource)]" | Out-File -FilePath $LOGFILE -Append
    }
}

Invoke-Step "Deshabilitar cuenta Administrator integrada si está activa" {
    $builtinAdmin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($builtinAdmin -and $builtinAdmin.Enabled) {
        Disable-LocalUser -Name "Administrator"
        Write-Log "[*] Cuenta Administrator integrada deshabilitada." $GREEN
    } else {
        Write-Log "[*] Cuenta Administrator ya deshabilitada o no existe." $YELLOW
    }
}

Invoke-Step "Activar auditoría extendida de uso de privilegios" {
    # Privilege Use: registrar elevaciones de privilegio exitosas y fallidas
    auditpol /set /subcategory:"Sensitive Privilege Use"    /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
    # Process Tracking: registrar creación de procesos (detecta ejecuciones sospechosas)
    auditpol /set /subcategory:"Process Creation"  /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Termination" /success:enable | Out-Null
    # Account Management
    auditpol /set /subcategory:"User Account Management"  /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable | Out-Null
    Write-Log "[*] Auditoría extendida de privilegios y procesos activada." $GREEN
}

Invoke-Step "Configurar tamaño máximo del Event Log de Seguridad (512 MB)" {
    $secLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
    if (Test-Path $secLogPath) {
        Set-ItemProperty -Path $secLogPath -Name "MaxSize" -Value 536870912  # 512 MB en bytes
        Write-Log "[*] Event Log de Seguridad configurado a 512 MB." $GREEN
    }
}

# ─────────────────────────────────────────────
# Finalización
# ─────────────────────────────────────────────
$ROLLBACK_NEEDED = $false

Write-Log "" $GREEN
Write-Log "══════════════════════════════════════════════════" $GREEN
if ($DryRun) {
    Write-Log "[DRY-RUN] Simulación completada. Ningún cambio fue aplicado." $CYAN
    Write-Log "          Ejecuta sin -DryRun para aplicar el hardening." $CYAN
} else {
    Write-Log "[+] Hardening v3.0 completado. Sistema securizado y optimizado." $GREEN
    Write-Log "[*] Log disponible en:    $LOGFILE" $YELLOW
    Write-Log "[*] Backups guardados en: $backupDir" $YELLOW
    Write-Log "[!] RECOMENDADO: Reiniciar el sistema para aplicar cambios TLS/SCHANNEL." $YELLOW

# Programar reinicio en 5 minutos si no estamos en DryRun
if (-not $DryRun) {
    Write-Log "[!] Programando reinicio automático en 5 minutos (shutdown /r /t 300)" $YELLOW
    # shutdown retorna 0 en éxito, redirigimos salida a null
    shutdown /r /t 300 /c "Fortress Hardening: reinicio necesario para aplicar cambios TLS/SCHANNEL" | Out-Null
} else {
    Write-Log "[DRY-RUN] Se simularía un reinicio en 5 minutos." $CYAN
}
}
Write-Log "══════════════════════════════════════════════════" $GREEN

if (-not $DryRun) {
    Read-Host "Presiona Enter para salir"
}