# Osint_recon
Script_éticos
#  OSINT Recon Tool — v1.1

> Herramienta de reconocimiento OSINT en Bash para uso **exclusivamente ético y en entornos autorizados**.

---

##  Aviso Legal

Esta herramienta está diseñada para **profesionales de ciberseguridad, investigadores y estudiantes** que cuenten con autorización explícita sobre los objetivos que analizan.

**Queda estrictamente prohibido:**
- Usarla contra personas, empresas o sistemas sin su consentimiento
- Recopilar datos personales con fines maliciosos o ilegales
- Utilizarla para acosar, suplantar o perjudicar a terceros

El uso indebido puede constituir un **delito informático** penado por la ley (España: art. 197 CP / GDPR / LOPDGDD). El autor no se responsabiliza del mal uso de esta herramienta.

---

##  Requisitos

| Herramienta | Instalación |
|-------------|-------------|
| `bash` | Incluido en Linux/macOS |
| `curl` | `sudo apt install curl` |
| `dig` | `sudo apt install dnsutils` |
| `whois` | `sudo apt install whois` |
| `nmap` *(opcional)* | `sudo apt install nmap` |
| `python3` | `sudo apt install python3` |

### Herramientas externas recomendadas (opcionales)

```bash
pip install holehe --break-system-packages        # Comprueba 120+ plataformas por email
pip install maigret --break-system-packages       # Búsqueda por username
pip install phoneinfoga --break-system-packages   # Análisis avanzado de teléfonos
pip install h8mail --break-system-packages        # Búsqueda de emails en brechas
```

---

##  Instalación

```bash
# Clonar o descargar el script
chmod +x osint.sh
```

---

##  Módulos disponibles

| Módulo | Flag | Descripción |
|--------|------|-------------|
| WHOIS | `--whois` | Información del registrador del dominio |
| DNS | `--dns` | Registros A, MX, TXT, NS, CNAME, SOA + AXFR |
| IP | `--ip` | Geolocalización, ISP, ASN, Reverse DNS |
| Cabeceras HTTP | `--headers` | Análisis de seguridad de headers HTTP |
| Robots / Archivos | `--robots` | robots.txt, sitemap, archivos sensibles expuestos |
| Emails expuestos | `--emails` | Emails encontrados en páginas públicas del dominio |
| Subdominios | `--subdomains` | Enumeración de subdominios por fuerza bruta |
| Puertos | `--ports` | Escaneo de puertos comunes (con nmap o /dev/tcp) |
| Lookup | `--lookup` | Busca en qué plataformas está registrado un email o teléfono |
| Todos | `--all` | Ejecuta todos los módulos anteriores |

---

##  Uso

### Sintaxis básica

```bash
./osint.sh -t <dominio|IP> [módulos] [opciones]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `-t`, `--target` | Dominio o IP objetivo (**obligatorio**) |
| `-l`, `--lookup-input` | Email o teléfono para el módulo `--lookup` |
| `-o`, `--output` | Guardar resultados en un archivo de texto |
| `-w`, `--wordlist` | Wordlist personalizada para subdominios |
| `-h`, `--help` | Mostrar ayuda |

---

##  Ejemplos de uso

### Reconocimiento completo de un dominio
```bash
./osint.sh -t ejemplo.com --all
```

### Solo WHOIS y DNS
```bash
./osint.sh -t ejemplo.com --whois --dns
```

### Analizar una IP directamente
```bash
./osint.sh -t 8.8.8.8 --ip --ports
```

### Subdominios con wordlist personalizada
```bash
./osint.sh -t ejemplo.com --subdomains -w /usr/share/wordlists/subdomains.txt
```

### Guardar el reporte en un archivo
```bash
./osint.sh -t ejemplo.com --all -o reporte.txt
```

### Buscar en qué plataformas está registrado un email
```bash
./osint.sh -t osint --lookup -l correo@gmail.com
```

### Buscar en qué plataformas está registrado un teléfono
```bash
./osint.sh -t osint --lookup -l +34612345678
```

---

##  Módulo Lookup — Detalle

El módulo `--lookup` permite investigar si un **email** o **teléfono** aparece registrado en distintas plataformas y bases de datos públicas.

### Para emails comprueba:
- **HaveIBeenPwned** — brechas de datos conocidas
- **Gravatar** — existencia de cuenta y username asociado
- **Firefox Accounts (Mozilla)** — verificación vía API pública
- **Proton Mail** — disponibilidad del nombre de usuario
- **EmailRep.io** — reputación, score de riesgo y perfiles asociados
- Genera dorks para Google, Bing, Dehashed, IntelX, Hunter.io

### Para teléfonos comprueba:
- **Numverify** — país, operadora y tipo de línea
- **WhatsApp** — enlace directo para verificar si el número está activo
- **Telegram** — enlace directo al perfil
- Links a TrueCaller, NumLookup, PhoneInfoga, Sync.me
- Instrucciones para verificar manualmente en Instagram, Facebook, Twitter/X, Snapchat

>  Para resultados más completos con emails, ejecuta también:
> ```bash
> holehe correo@gmail.com
> ```
> Holehe comprueba más de **120 plataformas** (Twitter, Instagram, Spotify, Netflix, Adobe, GitHub, Discord, Steam, Twitch, etc.)

---

##  Estructura del reporte

Cuando usas `-o reporte.txt`, el archivo generado contiene:

```
══════════════════════════════════════════════════
                OSINT Recon Report
══════════════════════════════════════════════════
  Objetivo : ejemplo.com
  Fecha    : 2025-01-01 12:00:00
══════════════════════════════════════════════════

[WHOIS] Domain Name: ejemplo.com
[DNS] A: 93.184.216.34
[IP-GEO] País: United States
[PORTS] 80/tcp open - HTTP
[LOOKUP] Tipo: Email - correo@ejemplo.com
...
```

---

##  Buenas prácticas éticas

1. **Obtén siempre autorización escrita** antes de analizar cualquier objetivo
2. **No almacenes datos personales** de terceros sin su consentimiento (GDPR)
3. Usa la herramienta en **entornos de prueba o tus propios sistemas**
4. Si encuentras vulnerabilidades, practica el **Responsible Disclosure**: notifica al afectado antes de publicar nada
5. No uses los resultados para **doxxing**, acoso o cualquier actividad ilegal

---

##  Casos de uso legítimos

- Auditorías de seguridad propias o con contrato firmado
- CTF (Capture The Flag) y retos de ciberseguridad
- Pentesting con autorización expresa del cliente
- Investigación académica y aprendizaje
- Verificar tu propia huella digital en internet

---

##  Licencia

Este proyecto es de uso libre para fines educativos y éticos.  
**Cualquier uso malintencionado es responsabilidad exclusiva del usuario.**
