# 🛡️ Zero-Touch Server Hardening

**Automatización de seguridad para Linux y Windows**
Diseñado bajo el principio de **máxima protección con mínima gestión manual**.

Este proyecto proporciona scripts que aplican una línea base de seguridad robusta en servidores y estaciones de trabajo, reduciendo la superficie de ataque de forma completamente automatizada. Incluye un entorno de pruebas aislado con Vagrant para validar cada cambio sin tocar sistemas reales.

---

## 📁 Estructura del proyecto

```
zero-touch-server-hardening/
├── fortress_hardening.sh          # Script principal para Linux (v3.0)
├── fortress_hardening.ps1         # Script principal para Windows (v3.0)
├── pruebas_hardening/
│   ├── linux/
│   │   ├── Vagrantfile            # Entorno de pruebas Linux (Ubuntu 20.04)
│   │   └── fortress_hardening.sh  # Copia del script para el lab
│   └── windows/
│       ├── Vagrantfile            # Entorno de pruebas Windows (Server 2019)
│       └── fortress_hardening.ps1 # Copia del script para el lab
└── README.md
```

---

## 🚀 Características

### 🔹 Linux (`fortress_hardening.sh` v3.0)

| Módulo | Descripción |
|---|---|
| **Modo `--dry-run`** | Previsualiza todos los cambios sin aplicar nada |
| **Detección de distro** | Soporta Debian/Ubuntu y RHEL/CentOS/Fedora automáticamente |
| **Firewall UFW** | Política deny-by-default; solo SSH, HTTP y HTTPS permitidos |
| **Hardening SSH** | Deshabilita root login, autenticación por contraseña y X11; fuerza claves públicas |
| **Cifrados SSH modernos** | Configura `KexAlgorithms`, `Ciphers` y `MACs` eliminando algoritmos obsoletos (arcfour, 3DES, MD5) |
| **Fail2Ban** | Jails para SSH, SSH-DDoS, recidive y servicios detectados automáticamente |
| **Kernel (sysctl)** | Protección contra IP spoofing, SYN flood, redirecciones ICMP y source routing |
| **Usuarios privilegiados** | Auditoría de usuarios sudo, hardening de sudoers (`log_output`, `requiretty`, `use_pty`) |
| **auditd** | Reglas de auditoría para cambios en `/etc/passwd`, `/etc/sudoers`, ejecuciones con setuid y claves SSH |
| **ClamAV** | Instalado, actualizado y programado para escaneo diario con cuarentena automática |
| **Actualizaciones automáticas** | `unattended-upgrades` configurado para parches de seguridad críticos |
| **Permisos de archivos** | Ajusta permisos en `/etc/shadow`, `/etc/passwd`, `/etc/group` y logs |
| **Backup automático** | Guarda configuraciones originales antes de cualquier cambio |
| **Log detallado** | Registro completo en `/var/log/fortress_hardening.log` |

### 🔸 Windows (`fortress_hardening.ps1` v3.0)

| Módulo | Descripción |
|---|---|
| **Modo `-DryRun`** | Previsualiza todos los cambios sin aplicar nada |
| **Reversión automática** | Si un paso crítico falla, restaura desde backup (directivas, firewall, RDP, SCHANNEL) |
| **Firewall de Windows** | Bloqueo por defecto; solo RDP, HTTP, HTTPS e ICMP permitidos |
| **Hardening RDP** | Activa NLA (Network Level Authentication) |
| **TLS/SCHANNEL** | Deshabilita SSL 2/3 y TLS 1.0/1.1; habilita TLS 1.2/1.3; elimina RC4, DES, 3DES, MD5 y SHA-1 |
| **Cipher suites TLS** | Configura orden moderno: AES-GCM, ChaCha20-Poly1305, solo ECDHE |
| **SMBv1 / LLMNR / NetBIOS** | Deshabilitados para eliminar vectores de ataque de red clásicos |
| **Bloqueo de cuentas** | 5 intentos fallidos → bloqueo 30 minutos |
| **Usuarios privilegiados** | Lista administradores locales, deshabilita la cuenta `Administrator` integrada |
| **Auditoría extendida** | `Sensitive Privilege Use`, `Process Creation` y `User Account Management` |
| **Windows Defender** | Firmas actualizadas, protección en tiempo real y escaneo diario programado |
| **Hardening TCP/IP** | SYN cookies, sin redirecciones ICMP, source routing deshabilitado |
| **UAC** | Habilitado con nivel de consentimiento para administradores |
| **Backup automático** | Exporta directivas, firewall y claves de registro SCHANNEL antes de modificar |
| **Log detallado** | Registro completo en `C:\ProgramData\fortress_hardening.log` |

---

## 📋 Requisitos

### Linux
- Sistema basado en **Debian/Ubuntu** o **RHEL/CentOS/Fedora**
- Permisos de **root** (el script lo verifica al inicio)
- Conexión a Internet para descargar paquetes

### Windows
- **Windows 10/11** (Pro/Enterprise) o **Windows Server 2016/2019/2022**
- Ejecución como **Administrador** (`#Requires -RunAsAdministrator`)
- Módulo `PSWindowsUpdate` (opcional, para actualizaciones automáticas):
  ```powershell
  Install-Module PSWindowsUpdate -Force
  ```
- Política de ejecución de scripts permitida:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  ```

---

## ⚙️ Uso en producción

### 🐧 Linux

```bash
# Clonar el repositorio
git clone https://github.com/AlejandroGlezSan/zero-touch-server-hardening.git
cd zero-touch-server-hardening

# (Opcional) Previsualizar cambios sin aplicar nada
sudo ./fortress_hardening.sh --dry-run

# Aplicar el hardening
sudo ./fortress_hardening.sh
```

### 🪟 Windows

```powershell
# (Opcional) Previsualizar cambios sin aplicar nada
.\fortress_hardening.ps1 -DryRun

# Aplicar el hardening
.\fortress_hardening.ps1
```

> ⚠️ **Se recomienda reiniciar el sistema tras la ejecución en Windows** para que los cambios de SCHANNEL/TLS tengan efecto completo.

---

## 🧪 Entorno de pruebas (Vagrant)

El proyecto incluye entornos de prueba aislados con Vagrant que levantan una VM limpia, aplican el hardening y ejecutan automáticamente una suite de tests que valida cada sección del script.

### Requisitos previos

- [Vagrant](https://www.vagrantup.com/downloads) >= 2.3
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) >= 6.1

### Lab Linux (Ubuntu 20.04)

```bash
cd pruebas_hardening/linux

# Asegúrate de que fortress_hardening.sh esté en esta carpeta
vagrant up                         # Levanta VM + hardening + tests
vagrant provision --provision-with 03-tests  # Re-ejecutar solo los tests
vagrant ssh                        # Acceder a la VM para inspección manual
vagrant reload                     # Reiniciar la VM
vagrant destroy -f                 # Eliminar la VM completamente
```

### Lab Windows (Windows Server 2019)

```bash
cd pruebas_hardening/windows

# Asegúrate de que fortress_hardening.ps1 esté en esta carpeta
# La box se descarga automáticamente (~7 GB la primera vez)
vagrant up
vagrant provision --provision-with 03-tests
vagrant destroy -f
```

### Suite de tests

Ambos entornos ejecutan tests automáticos al finalizar el provisioning e imprimen un resumen con `[PASS]`, `[FAIL]` y `[WARN]` por cada verificación.

**Linux** — 48 tests en 12 secciones:

- Paquetes instalados (fail2ban, ufw, clamav, auditd…)
- Servicios activos
- Reglas UFW y política por defecto
- 10 directivas SSH + cifrados modernos (KexAlgorithms, Ciphers, MACs)
- Jails de Fail2Ban (sshd, recidive)
- 7 parámetros sysctl del kernel
- Permisos de archivos críticos
- Configuración de unattended-upgrades
- auditd activo y reglas cargadas
- Hardening de sudoers
- ClamAV y cron diario
- Directorio de backup generado

**Windows** — 11 secciones:

- Perfiles de firewall y reglas (RDP, HTTP, HTTPS, SMB)
- NLA en RDP
- Lockout policy (5 intentos, 30 min)
- Windows Defender + tarea diaria programada
- SMBv1, LLMNR y NetBIOS deshabilitados
- SCHANNEL: protocolos deshabilitados (SSL 2/3, TLS 1.0/1.1) y cifrados débiles eliminados
- Parámetros TCP/IP (SynAttackProtect, ICMPRedirect, SourceRouting)
- UAC habilitado
- Cuenta Administrator integrada deshabilitada
- Auditoría extendida (Privilege Use, Process Creation)
- Log de hardening y directorio de backup presentes

---

## 📂 Proyectos relacionados en GitHub

| Proyecto | Descripción |
|---|---|
| [`ansible-multilang-automation`](https://github.com/AlejandroGlezSan/ansible-multilang-automation) | Infraestructura como código con Ansible para automatización multilenguaje |
| [`homelab-dashboard-node`](https://github.com/AlejandroGlezSan/homelab-dashboard-node) | Dashboard ligero para monitorización de servidores (CPU, RAM, disco) |
| [`multisite-network-monitor`](https://github.com/AlejandroGlezSan/multisite-network-monitor) | Sistema de monitorización centralizada para redes corporativas con Python |
| [`composeviz`](https://github.com/AlejandroGlezSan/composeviz) | Visualizador interactivo de archivos `docker-compose.yml` |

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.