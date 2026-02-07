#!/bin/bash

# =================================================================
# Project: Zero-Touch Server Hardening
# Author: Alejandro González Santana
# Purpose: Automated baseline security for Linux environments.
# =================================================================

# Colores para el output (porque el estilo importa en las demos)
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[+] Iniciando protocolo de Hardening...${NC}"

# 1. Actualización de seguridad silenciosa
echo -e "${GREEN}[+] Actualizando repositorios y parches de seguridad...${NC}"
sudo apt-get update -y && sudo apt-get upgrade -y

# 2. Instalación de armamento defensivo
echo -e "${GREEN}[+] Instalando Fail2Ban, UFW y ClamAV...${NC}"
sudo apt-get install -y fail2ban ufw clamav clamav-daemon

# 3. Configuración del Firewall (UFW)
# Permitimos lo esencial, bloqueamos el resto.
echo -e "${GREEN}[+] Configurando Firewall perimetral...${NC}"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
echo "y" | sudo ufw enable

# 4. Hardening de SSH (Evitar ataques de fuerza bruta)
echo -e "${GREEN}[+] Securizando servicio SSH mediante Fail2Ban...${NC}"
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Crear configuración personalizada para SSH en Fail2Ban
sudo bash -c 'cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
EOF'

sudo systemctl restart fail2ban

# 5. Limpieza y reporte final
echo -e "${GREEN}[+] Hardening completado. Sistema securizado y optimizado.${NC}"
echo -e "${GREEN}[!] Recuerda: La mejor seguridad es la que no requiere intervención.${NC}"
