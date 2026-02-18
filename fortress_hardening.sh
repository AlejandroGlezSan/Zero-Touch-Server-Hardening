#!/bin/bash
# =================================================================
# Project: Zero-Touch Server Hardening v2.0
# Author: Alejandro González Santana (Improved)
# Purpose: Comprehensive automated security baseline for Linux.
# =================================================================

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

LOGFILE="/var/log/fortress_hardening.log"

# Función para loguear y mostrar mensajes
log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

# Verificar ejecución como root
if [[ $EUID -ne 0 ]]; then
   log "${RED}[!] Este script debe ejecutarse como root.${NC}"
   exit 1
fi

log "${GREEN}[+] Iniciando protocolo de Hardening v2.0...${NC}"

# Backup de configuraciones importantes
backup_dir="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"
log "${YELLOW}[*] Creando backup en $backup_dir${NC}"
cp -r /etc/ssh /etc/fail2ban /etc/ufw /etc/sysctl.conf "$backup_dir" 2>/dev/null

# 1. Actualización de seguridad
log "${GREEN}[+] Actualizando repositorios y aplicando parches...${NC}"
apt-get update -y >> "$LOGFILE" 2>&1
apt-get upgrade -y >> "$LOGFILE" 2>&1

# 2. Instalación de paquetes esenciales
log "${GREEN}[+] Instalando herramientas de seguridad...${NC}"
apt-get install -y fail2ban ufw clamav clamav-daemon unattended-upgrades apt-listchanges >> "$LOGFILE" 2>&1

# 3. Configuración de actualizaciones automáticas de seguridad
log "${GREEN}[+] Configurando unattended-upgrades...${NC}"
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# 4. Configuración del Firewall (UFW)
log "${GREEN}[+] Configurando firewall UFW...${NC}"
ufw --force disable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
echo "y" | ufw enable >> "$LOGFILE" 2>&1
ufw status verbose | tee -a "$LOGFILE"

# 5. Hardening de SSH
log "${GREEN}[+] Reforzando configuración de SSH...${NC}"
# Backup original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
# Aplicar configuraciones seguras
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
# Añadir líneas si no existen
grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
systemctl restart sshd >> "$LOGFILE" 2>&1

# 6. Configuración Fail2Ban avanzada
log "${GREEN}[+] Configurando Fail2Ban con múltiples jails...${NC}"
systemctl enable fail2ban
# Jail local con configuraciones comunes
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
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
maxretry = 3
EOF

# Habilitar jails para servicios comunes si existen
for service in apache nginx proftpd vsftpd dovecot postfix; do
    if systemctl list-unit-files | grep -q "$service"; then
        echo "
[$service]
enabled = true
port = $service
logpath = /var/log/$service/*.log
" >> /etc/fail2ban/jail.local
    fi
done

systemctl restart fail2ban >> "$LOGFILE" 2>&1

# 7. Hardening del kernel (sysctl)
log "${GREEN}[+] Aplicando parámetros seguros al kernel...${NC}"
cat >> /etc/sysctl.d/99-hardening.conf <<EOF
# Protección contra IP spoofing
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
net.ipv4.tcp_tw_reuse = 1
EOF
sysctl -p /etc/sysctl.d/99-hardening.conf >> "$LOGFILE" 2>&1

# 8. Configuración de ClamAV y programación de escaneo
log "${GREEN}[+] Configurando ClamAV y actualizando firmas...${NC}"
systemctl stop clamav-freshclam
freshclam --quiet >> "$LOGFILE" 2>&1
systemctl start clamav-freshclam
systemctl enable clamav-freshclam

# Crear script de escaneo diario
cat > /usr/local/bin/clamav_daily_scan.sh <<'EOF'
#!/bin/bash
LOGFILE="/var/log/clamav/daily_scan.log"
SCAN_DIR="/home /var/www /tmp /var/tmp"
EMAIL="root@localhost"
echo "$(date) - Iniciando escaneo de ClamAV" >> "$LOGFILE"
/usr/bin/clamscan -r $SCAN_DIR --quiet --log="$LOGFILE" --move=/quarantine
if [ $? -ne 0 ]; then
    echo "Se encontraron amenazas. Revisa $LOGFILE" | mail -s "ClamAV Alert" $EMAIL
fi
EOF
chmod +x /usr/local/bin/clamav_daily_scan.sh
mkdir -p /quarantine /var/log/clamav

# Añadir cron diario a las 2am
echo "0 2 * * * root /usr/local/bin/clamav_daily_scan.sh" > /etc/cron.d/clamav_daily

# 9. Asegurar permisos de archivos críticos
log "${GREEN}[+] Ajustando permisos en archivos sensibles...${NC}"
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 640 /var/log/auth.log
chmod 640 /var/log/syslog
chown root:adm /var/log/auth.log /var/log/syslog

# 10. Limpieza y reporte final
log "${GREEN}[+] Hardening completado. Sistema securizado y optimizado.${NC}"
log "${GREEN}[!] Recuerda: La mejor seguridad es la que no requiere intervención.${NC}"
log "${YELLOW}[*] Log disponible en: $LOGFILE${NC}"
log "${YELLOW}[*] Backups guardados en: $backup_dir${NC}"