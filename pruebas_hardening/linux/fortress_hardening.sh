#!/bin/bash
# =================================================================
# Project: Zero-Touch Server Hardening v3.0
# Author: Alejandro González Santana
# Purpose: Comprehensive automated security baseline for Linux.
# Mejoras v3.0:
#   - Modo --dry-run: previsualiza cambios sin aplicarlos
#   - Hardening SSH completo: cifrados, MACs y KexAlgorithms modernos
#   - Gestión de usuarios privilegiados: auditoría sudo + auditd
# =================================================================

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/fortress_hardening.log"
DRY_RUN=false

# ─────────────────────────────────────────────
# Parseo de argumentos
# ─────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Uso: $0 [--dry-run]"
            echo ""
            echo "  --dry-run   Muestra los cambios que se aplicarían sin ejecutar nada."
            echo "  --help      Muestra esta ayuda."
            exit 0
            ;;
    esac
done

# ─────────────────────────────────────────────
# Funciones base
# ─────────────────────────────────────────────
log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

# Ejecuta un comando o lo simula según el modo
run() {
    if [ "$DRY_RUN" = true ]; then
        log "${CYAN}[DRY-RUN] Ejecutaría: $*${NC}"
    else
        eval "$@" >> "$LOGFILE" 2>&1
    fi
}

# Escribe en un archivo o simula según el modo
write_file() {
    local file="$1"
    local content="$2"
    if [ "$DRY_RUN" = true ]; then
        log "${CYAN}[DRY-RUN] Escribiría en $file:${NC}"
        echo "$content" | sed 's/^/    /'
    else
        echo "$content" > "$file"
    fi
}

append_file() {
    local file="$1"
    local content="$2"
    if [ "$DRY_RUN" = true ]; then
        log "${CYAN}[DRY-RUN] Añadiría a $file:${NC}"
        echo "$content" | sed 's/^/    /'
    else
        echo "$content" >> "$file"
    fi
}

# ─────────────────────────────────────────────
# Verificaciones previas
# ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
   log "${RED}[!] Este script debe ejecutarse como root.${NC}"
   exit 1
fi

if [ "$DRY_RUN" = true ]; then
    log "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    log "${CYAN}║         MODO DRY-RUN: sin cambios reales         ║${NC}"
    log "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
fi

log "${GREEN}[+] Iniciando protocolo de Hardening v3.0...${NC}"

# ─────────────────────────────────────────────
# Detección de distribución y gestor de paquetes
# ─────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            PM_UPDATE="apt-get update -y"
            PM_UPGRADE="apt-get upgrade -y"
            PM_INSTALL="apt-get install -y"
            ;;
        centos|rhel|fedora)
            if command -v dnf >/dev/null 2>&1; then
                PM_UPDATE="dnf makecache"
                PM_UPGRADE="dnf upgrade -y"
                PM_INSTALL="dnf install -y"
            else
                PM_UPDATE="yum makecache"
                PM_UPGRADE="yum update -y"
                PM_INSTALL="yum install -y"
            fi
            ;;
        *)
            log "${YELLOW}[!] Distro $ID desconocida, usando apt-get como fallback.${NC}"
            PM_UPDATE="apt-get update -y"
            PM_UPGRADE="apt-get upgrade -y"
            PM_INSTALL="apt-get install -y"
            ;;
    esac
else
    log "${YELLOW}[!] /etc/os-release no encontrado; asumimos Debian/Ubuntu.${NC}"
    PM_UPDATE="apt-get update -y"
    PM_UPGRADE="apt-get upgrade -y"
    PM_INSTALL="apt-get install -y"
fi

log "${YELLOW}[*] Utilizando gestor de paquetes: ${PM_UPDATE%% *}${NC}"

# ─────────────────────────────────────────────
# Backup de configuraciones importantes
# ─────────────────────────────────────────────
backup_dir="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] Crearía backup en $backup_dir${NC}"
else
    mkdir -p "$backup_dir"
    log "${YELLOW}[*] Creando backup en $backup_dir${NC}"
    cp -r /etc/ssh /etc/fail2ban /etc/ufw /etc/sysctl.conf "$backup_dir" 2>/dev/null
    cp /etc/sudoers "$backup_dir/sudoers.bak" 2>/dev/null
fi

# ─────────────────────────────────────────────
# 1. Actualización de seguridad
# ─────────────────────────────────────────────
log "${GREEN}[+] Actualizando repositorios y aplicando parches...${NC}"
run "$PM_UPDATE"
run "$PM_UPGRADE"

# ─────────────────────────────────────────────
# 2. Instalación de paquetes esenciales
# ─────────────────────────────────────────────
log "${GREEN}[+] Instalando herramientas de seguridad...${NC}"
run "$PM_INSTALL fail2ban ufw clamav clamav-daemon unattended-upgrades apt-listchanges auditd audispd-plugins"

# ─────────────────────────────────────────────
# 3. Actualizaciones automáticas de seguridad
# ─────────────────────────────────────────────
log "${GREEN}[+] Configurando unattended-upgrades...${NC}"
write_file "/etc/apt/apt.conf.d/50unattended-upgrades" \
'Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";'

write_file "/etc/apt/apt.conf.d/20auto-upgrades" \
'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";'

# ─────────────────────────────────────────────
# 4. Firewall (UFW)
# ─────────────────────────────────────────────
log "${GREEN}[+] Configurando firewall UFW...${NC}"
if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] ufw default deny incoming${NC}"
    log "${CYAN}[DRY-RUN] ufw default allow outgoing${NC}"
    log "${CYAN}[DRY-RUN] ufw allow ssh / http / https${NC}"
    log "${CYAN}[DRY-RUN] ufw enable${NC}"
else
    ufw --force disable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    echo "y" | ufw enable >> "$LOGFILE" 2>&1
    ufw status verbose | tee -a "$LOGFILE"
fi

# ─────────────────────────────────────────────
# 5. Hardening de SSH (MEJORADO)
#    - Cifrados, MACs y KexAlgorithms modernos
#    - Eliminación de algoritmos obsoletos
# ─────────────────────────────────────────────
log "${GREEN}[+] Reforzando configuración de SSH (cifrados modernos)...${NC}"

if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] Aplicaría las siguientes directivas en /etc/ssh/sshd_config:${NC}"
    cat <<'EOF' | sed 's/^/    /'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
AllowAgentForwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
Protocol 2
# Algoritmos modernos (NUEVO v3.0):
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF
else
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Directivas básicas
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

    # Añadir directivas si no existen
    grep -q "^MaxAuthTries"           /etc/ssh/sshd_config || echo "MaxAuthTries 3"           >> /etc/ssh/sshd_config
    grep -q "^ClientAliveInterval"    /etc/ssh/sshd_config || echo "ClientAliveInterval 300"  >> /etc/ssh/sshd_config
    grep -q "^ClientAliveCountMax"    /etc/ssh/sshd_config || echo "ClientAliveCountMax 2"    >> /etc/ssh/sshd_config
    grep -q "^LoginGraceTime"         /etc/ssh/sshd_config || echo "LoginGraceTime 30"        >> /etc/ssh/sshd_config
    grep -q "^AllowAgentForwarding"   /etc/ssh/sshd_config || echo "AllowAgentForwarding no"  >> /etc/ssh/sshd_config
    grep -q "^AllowTcpForwarding"     /etc/ssh/sshd_config || echo "AllowTcpForwarding no"    >> /etc/ssh/sshd_config
    grep -q "^PermitEmptyPasswords"   /etc/ssh/sshd_config || echo "PermitEmptyPasswords no"  >> /etc/ssh/sshd_config
    grep -q "^Protocol"               /etc/ssh/sshd_config || echo "Protocol 2"               >> /etc/ssh/sshd_config

    # ── Algoritmos criptográficos modernos (NUEVO v3.0) ──────────────────
    # Eliminar entradas antiguas si existen y añadir las nuevas
    sed -i '/^KexAlgorithms/d' /etc/ssh/sshd_config
    sed -i '/^Ciphers/d'       /etc/ssh/sshd_config
    sed -i '/^MACs/d'          /etc/ssh/sshd_config

    cat >> /etc/ssh/sshd_config <<'SSHEOF'

# ── Criptografía moderna (v3.0) ──────────────────────────────────────────
# Intercambio de claves: solo curvas elípticas y DH grupos grandes
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
# Cifrados: solo AEAD (autenticados y cifrados) o CTR con AES >= 128 bits
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
# MACs: solo variantes ETM (encrypt-then-MAC) con SHA-2
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
SSHEOF

    systemctl restart sshd >> "$LOGFILE" 2>&1
    log "${GREEN}[+] SSH reforzado con algoritmos modernos.${NC}"
fi

# ─────────────────────────────────────────────
# 6. Fail2Ban
# ─────────────────────────────────────────────
log "${GREEN}[+] Configurando Fail2Ban con múltiples jails...${NC}"
run "systemctl enable fail2ban"

write_file "/etc/fail2ban/jail.local" \
'[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
destemail = root@localhost
sender = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 5

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime = 1d
findtime = 1d
maxretry = 3'

if [ "$DRY_RUN" = false ]; then
    for service in apache nginx proftpd vsftpd dovecot postfix; do
        if systemctl list-unit-files | grep -q "$service"; then
            cat >> /etc/fail2ban/jail.local <<EOF

[$service]
enabled = true
port = $service
logpath = /var/log/$service/*.log
EOF
        fi
    done
    systemctl restart fail2ban >> "$LOGFILE" 2>&1
else
    log "${CYAN}[DRY-RUN] Detectaría servicios activos y añadiría sus jails automáticamente.${NC}"
fi

# ─────────────────────────────────────────────
# 7. Hardening del kernel (sysctl)
# ─────────────────────────────────────────────
log "${GREEN}[+] Aplicando parámetros seguros al kernel...${NC}"
append_file "/etc/sysctl.d/99-hardening.conf" \
'# Protección contra IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignorar redirecciones ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
# Ignorar peticiones ICMP de router
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Habilitar protección contra SYN flood
net.ipv4.tcp_syncookies = 1
# Deshabilitar source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
# Log de paquetes marcianos
net.ipv4.conf.all.log_martians = 1
# Ignorar peticiones ICMP echo broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignorar respuestas ICMP bogus
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Aumentar rango de puertos efímeros
net.ipv4.ip_local_port_range = 32768 65535
# Reducir timeouts
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1'

run "sysctl -p /etc/sysctl.d/99-hardening.conf"

# ─────────────────────────────────────────────
# 8. ClamAV
# ─────────────────────────────────────────────
log "${GREEN}[+] Configurando ClamAV y actualizando firmas...${NC}"
if [ "$DRY_RUN" = false ]; then
    systemctl stop clamav-freshclam
    freshclam --quiet >> "$LOGFILE" 2>&1
    systemctl start clamav-freshclam
    systemctl enable clamav-freshclam
    mkdir -p /quarantine /var/log/clamav
fi

write_file "/usr/local/bin/clamav_daily_scan.sh" \
'#!/bin/bash
LOGFILE="/var/log/clamav/daily_scan.log"
SCAN_DIR="/home /var/www /tmp /var/tmp"
EMAIL="root@localhost"
echo "$(date) - Iniciando escaneo de ClamAV" >> "$LOGFILE"
/usr/bin/clamscan -r $SCAN_DIR --quiet --log="$LOGFILE" --move=/quarantine
if [ $? -ne 0 ]; then
    echo "Se encontraron amenazas. Revisa $LOGFILE" | mail -s "ClamAV Alert" $EMAIL
fi'

run "chmod +x /usr/local/bin/clamav_daily_scan.sh"

if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] Añadiría cron diario a las 2am para ClamAV.${NC}"
else
    echo "0 2 * * * root /usr/local/bin/clamav_daily_scan.sh" > /etc/cron.d/clamav_daily
fi

# ─────────────────────────────────────────────
# 9. Permisos de archivos críticos
# ─────────────────────────────────────────────
log "${GREEN}[+] Ajustando permisos en archivos sensibles...${NC}"
run "chmod 600 /etc/shadow"
run "chmod 600 /etc/gshadow"
run "chmod 644 /etc/passwd"
run "chmod 644 /etc/group"
run "chmod 640 /var/log/auth.log"
run "chmod 640 /var/log/syslog"
run "chown root:adm /var/log/auth.log /var/log/syslog"

# ─────────────────────────────────────────────
# 10. Gestión de usuarios privilegiados + auditd (NUEVO v3.0)
# ─────────────────────────────────────────────
log "${GREEN}[+] Auditando usuarios con privilegios sudo...${NC}"

if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] Listaría usuarios con acceso sudo:${NC}"
    log "${CYAN}[DRY-RUN]   getent group sudo | cut -d: -f4${NC}"
    log "${CYAN}[DRY-RUN] Verificaría configuración de sudoers (requiretty, log_output).${NC}"
    log "${CYAN}[DRY-RUN] Instalaría y activaría auditd con reglas para:${NC}"
    log "${CYAN}[DRY-RUN]   - Uso de sudo (execve)${NC}"
    log "${CYAN}[DRY-RUN]   - Cambios en /etc/passwd, /etc/shadow, /etc/sudoers${NC}"
    log "${CYAN}[DRY-RUN]   - Escalada de privilegios${NC}"
else
    # ── 10a. Informe de usuarios sudo actuales ────────────────────────────
    log "${YELLOW}[*] Usuarios con acceso sudo actualmente:${NC}"
    sudo_users=$(getent group sudo | cut -d: -f4)
    if [ -z "$sudo_users" ]; then
        log "${YELLOW}    (ninguno en grupo sudo)${NC}"
    else
        echo "    $sudo_users" | tr ',' '\n' | while read u; do
            log "${YELLOW}    - $u${NC}"
        done
    fi
    log "${YELLOW}[*] Entradas en sudoers con privilegios completos:${NC}"
    grep -v '^#' /etc/sudoers | grep 'ALL=(ALL' | tee -a "$LOGFILE" | sed 's/^/    /'

    # ── 10b. Hardening de sudoers ─────────────────────────────────────────
    # Registrar todos los comandos ejecutados via sudo
    grep -q "^Defaults.*log_output"  /etc/sudoers || echo "Defaults   log_output"        >> /etc/sudoers
    grep -q "^Defaults.*logfile"     /etc/sudoers || echo 'Defaults   logfile="/var/log/sudo.log"' >> /etc/sudoers
    grep -q "^Defaults.*requiretty"  /etc/sudoers || echo "Defaults   requiretty"         >> /etc/sudoers
    grep -q "^Defaults.*use_pty"     /etc/sudoers || echo "Defaults   use_pty"            >> /etc/sudoers
    chmod 640 /var/log/sudo.log 2>/dev/null || touch /var/log/sudo.log && chmod 640 /var/log/sudo.log
    log "${GREEN}[+] sudoers configurado con log_output, requiretty y use_pty.${NC}"

    # ── 10c. auditd: reglas de auditoría de privilegios ──────────────────
    systemctl enable auditd >> "$LOGFILE" 2>&1
    systemctl start  auditd >> "$LOGFILE" 2>&1

    cat > /etc/audit/rules.d/99-hardening.rules <<'AUDITEOF'
# ── Reglas de auditoría fortress_hardening v3.0 ──────────────────────────

# Cambios en archivos de autenticación y usuarios
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/sudoers  -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Uso de sudo y su (escalada de privilegios)
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su   -p x -k privilege_escalation

# Ejecuciones con setuid/setgid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid_exec

# Cambios en claves SSH
-w /root/.ssh -p wa -k root_ssh
-w /home      -p wa -k user_ssh_keys

# Cargas de módulos del kernel
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules

# Hacer las reglas inmutables (requiere reboot para cambiarlas)
-e 2
AUDITEOF

    augenrules --load >> "$LOGFILE" 2>&1
    log "${GREEN}[+] auditd configurado y reglas cargadas.${NC}"
fi

# ─────────────────────────────────────────────
# Función: verificación post-hardening
# ─────────────────────────────────────────────
verify_post_hardening() {
    log "${GREEN}[+] Iniciando verificación post-hardening...${NC}"
    local ok=0

    if grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config; then
        log "    SSH PasswordAuthentication no: ✅"
    else
        log "    SSH PasswordAuthentication no: ❌"
        ok=1
    fi

    if ufw status | grep -q 'Status: active'; then
        log "    UFW activo: ✅"
    else
        log "    UFW activo: ❌"
        ok=1
    fi

    if systemctl is-active --quiet fail2ban; then
        log "    Fail2Ban corriendo: ✅"
    else
        log "    Fail2Ban corriendo: ❌"
        ok=1
    fi

    # añadir más comprobaciones según necesidad
    if [ $ok -eq 0 ]; then
        log "${GREEN}[+] Todas las comprobaciones pasaron.${NC}"
    else
        log "${RED}[!] Algunas comprobaciones fallaron. Revisa el log para detalles.${NC}"
    fi
}

# ─────────────────────────────────────────────
# Reporte final
# ─────────────────────────────────────────────
log ""
log "${GREEN}══════════════════════════════════════════════════${NC}"
if [ "$DRY_RUN" = true ]; then
    log "${CYAN}[DRY-RUN] Simulación completada. Ningún cambio fue aplicado.${NC}"
    log "${CYAN}          Ejecuta sin --dry-run para aplicar el hardening.${NC}"
else
    log "${GREEN}[+] Hardening v3.0 completado. Sistema securizado.${NC}"
    log "${YELLOW}[*] Log disponible en:   $LOGFILE${NC}"
    log "${YELLOW}[*] Backups guardados en: $backup_dir${NC}"
    log "${YELLOW}[*] Log sudo en:          /var/log/sudo.log${NC}"
    log "${YELLOW}[*] Log auditd en:        /var/log/audit/audit.log${NC}"
fi
log "${GREEN}══════════════════════════════════════════════════${NC}"