# 🛡️ Zero-Touch Server Hardening

**Automatización de seguridad para Linux y Windows**  
Diseñado bajo el principio de **máxima protección con mínima gestión manual**.  
Este proyecto proporciona scripts que aplican configuraciones de seguridad esenciales en servidores y estaciones de trabajo, reduciendo la superficie de ataque y estableciendo una línea base robusta.

---

## 🚀 Características

### 🔹 Versión para Linux (`fortress_hardening.sh` v2.0)
- **Parches automáticos:** Actualización de paquetes y repositorios.
- **Firewall dinámico:** Configuración estricta de UFW (denegar por defecto, permitir solo SSH/HTTP/HTTPS).
- **Protección contra fuerza bruta:** Fail2Ban con jails para SSH y otros servicios detectados automáticamente.
- **Refuerzo de SSH:** Desactiva login root, autenticación por contraseña y X11Forwarding; fuerza uso de claves.
- **Actualizaciones de seguridad automáticas:** `unattended-upgrades` configurado para parches críticos.
- **Hardening del kernel:** Parámetros `sysctl` contra IP spoofing, SYN flood, redirecciones ICMP, etc.
- **Antivirus:** ClamAV instalado, actualizado y programado para escaneo diario (con cuarentena y alertas por correo).
- **Permisos seguros:** Ajusta permisos en archivos críticos del sistema.
- **Backup automático:** Guarda configuraciones originales antes de cualquier cambio.
- **Log detallado:** Registro de todas las acciones en `/var/log/fortress_hardening.log`.

### 🔸 Versión para Windows (`fortress_hardening.ps1`)
- **Actualizaciones del sistema:** Opcional mediante módulo `PSWindowsUpdate`.
- **Firewall de Windows:** Reglas entrantes bloqueadas por defecto; solo se permiten RDP, HTTP, HTTPS e ICMP.
- **Protección RDP:** Activa NLA (Network Level Authentication), posibilidad de cambiar puerto.
- **Política de bloqueo de cuentas:** 5 intentos fallidos → bloqueo 30 minutos (configurable).
- **Windows Defender:** Actualización de firmas, protección en tiempo real, escaneo rápido diario programado.
- **Desactivación de protocolos inseguros:** SMBv1, LLMNR, NetBIOS sobre TCP/IP.
- **Hardening de red:** Parámetros TCP/IP (SYN cookies, deshabilitar redirecciones ICMP, etc.).
- **Auditoría básica:** Eventos de inicio de sesión y gestión de cuentas auditados.
- **UAC reforzado:** Control de cuentas de usuario activado con nivel de consentimiento adecuado.
- **Backup de configuraciones:** Exporta directivas de seguridad, firewall y registro RDP.
- **Log en `C:\ProgramData\fortress_hardening.log`** con toda la trazabilidad.

---

## 📋 Requisitos previos

### Para Linux
- Sistema basado en **Debian/Ubuntu** (funciona en derivados como Linux Mint, Pop!_OS, etc.).
- Permisos de **root** (el script verifica y aborta si no).
- Conexión a Internet para descargar paquetes.

### Para Windows
- **Windows 10/11** (Pro/Enterprise) o **Windows Server 2016/2019/2022**.
- Ejecución como **Administrador** (el script lo exige).
- Módulo `PSWindowsUpdate` (opcional, para actualizaciones automáticas). Instalar con:
  ```powershell
  Install-Module PSWindowsUpdate -Force
  ```
- Política de ejecución de scripts permitida (temporalmente: `Set-ExecutionPolicy Bypass -Scope Process`).

---

## ⚙️ Uso

### 🐧 Linux
1. Descarga o crea el archivo `fortress_hardening.sh`.
2. Dale permisos de ejecución:
   ```bash
   chmod +x fortress_hardening.sh
   ```
3. Ejecuta como root:
   ```bash
   sudo ./fortress_hardening.sh
   ```
   O directamente con usuario root:
   ```bash
   ./fortress_hardening.sh
   ```

### 🪟 Windows
1. Guarda el script como `fortress_hardening.ps1`.
2. Abre **PowerShell como Administrador**.
3. Permite la ejecución para la sesión actual:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   ```
4. Ejecuta:
   ```powershell
   .\fortress_hardening.ps1
   ```

El script mostrará cada paso con colores y generará un log en la ruta indicada.

---

## 🔍 Verificaciones post-ejecución

### Linux
- Estado del firewall: `sudo ufw status verbose`
- Reglas de Fail2Ban: `sudo fail2ban-client status`
- Configuración SSH: `sudo sshd -T | grep -E "permitrootlogin|passwordauthentication"`
- Parámetros del kernel: `sysctl -a | grep -E "rp_filter|accept_redirects|tcp_syncookies"`
- Escaneo de ClamAV programado: `crontab -l` o revisar `/etc/cron.d/clamav_daily`

### Windows
- Reglas de firewall: `Get-NetFirewallRule -Enabled True`
- Estado de RDP: `Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication`
- Política de bloqueo: `net accounts`
- Defender: `Get-MpPreference`
- Protocolos deshabilitados: `Get-SmbServerConfiguration | Select EnableSMB1Protocol` y `Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast`

---

## 📁 Archivos generados

### Linux
- **Log:** `/var/log/fortress_hardening.log`
- **Backup:** `/root/hardening_backup_AAAAMMDD_HHMMSS/`
- **Configuración personalizada de Fail2Ban:** `/etc/fail2ban/jail.local`
- **Parámetros del kernel:** `/etc/sysctl.d/99-hardening.conf`
- **Script de escaneo ClamAV:** `/usr/local/bin/clamav_daily_scan.sh`

### Windows
- **Log:** `C:\ProgramData\fortress_hardening.log`
- **Backup:** `C:\HardeningBackup_AAAAMMDD_HHMMSS\` (contiene `security_policy.inf`, `firewall.wfw`, `rdp.reg`)
- **Tarea programada de Defender:** "Windows Defender Daily Quick Scan" (a las 3:00 AM)

---

## ⚠️ Advertencias y personalización

- **Reversión:** Si algo falla, restaura desde el backup o el snapshot de la máquina virtual.
- **Entornos productivos:** Prueba siempre en un entorno de staging antes de aplicar en producción.
- **Personalización:**
  - **Linux:** Puedes modificar los puertos permitidos en UFW editando las líneas `ufw allow ...`. Para añadir más jails a Fail2Ban, edita `/etc/fail2ban/jail.local`.
  - **Windows:** Cambia el puerto RDP descomentando las líneas correspondientes. Ajusta la política de bloqueo modificando los valores en el bloque de `secedit`.
- **Correo electrónico:** En Linux, las alertas de ClamAV se envían a `root@localhost`. Configura un relay si deseas notificaciones externas.
- **Módulo PSWindowsUpdate:** Si no está instalado, el script omite la actualización automática sin interrumpir el resto del proceso.

---

## 🤝 Contribuciones

Las sugerencias y mejoras son bienvenidas. Si encuentras algún error o deseas añadir nuevas funcionalidades, abre un issue o envía un pull request.

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
