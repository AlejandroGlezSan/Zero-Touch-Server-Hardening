# 🛡️ Zero-Touch Server Hardening

Este script automatiza el despliegue de medidas de seguridad esenciales en entornos Linux (Debian/Ubuntu). Diseñado bajo el principio de **máxima protección con mínima gestión manual**.

### Funcionalidades:
* **Parches Automáticos:** Actualización integral de paquetes críticos.
* **Firewall Dinámico:** Configuración estricta de UFW (Default Deny).
* **Intrusion Prevention:** Despliegue de Fail2Ban con políticas de baneo agresivas para SSH.
* **Endpoint Protection:** Instalación de ClamAV para escaneo de malware.

### Uso:
`chmod +x fortress_hardening.sh && ./fortress_hardening.sh`
