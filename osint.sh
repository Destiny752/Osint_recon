#!/bin/bash

# ══════════════════════════════════════════════════════════════
#                     OSINT Recon Tool
#                   Versión Bash - v1.0
#         Solo para uso ético y en entornos autorizados
# ══════════════════════════════════════════════════════════════

# ─── Colores ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
GRAY='\033[0;90m'
RESET='\033[0m'

# ─── Variables globales ────────────────────────────────────────
TARGET=""
TARGET_IP=""       # IP resuelta o la propia IP si es target directo
IS_IP=false        # true si el target es una IP directamente
OUTPUT_FILE=""
WORDLIST=""
RUN_ALL=false
MOD_WHOIS=false
MOD_DNS=false
MOD_SUBDOMAINS=false
MOD_HEADERS=false
MOD_ROBOTS=false
MOD_EMAILS=false
MOD_IP=false
MOD_PORTS=false
MOD_LOOKUP=false
LOOKUP_INPUT=""     # Email o teléfono a investigar
RESULTS=()

# ─── Detectar si el target es una IP ──────────────────────────
is_ip() {
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    [[ "$1" =~ $regex ]]
}

# Resolver IP del target (dominio o IP directa)
resolve_target_ip() {
    if is_ip "$TARGET"; then
        IS_IP=true
        TARGET_IP="$TARGET"
    else
        IS_IP=false
        TARGET_IP=$(dig +short A "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        if [[ -z "$TARGET_IP" ]]; then
            TARGET_IP=$(host "$TARGET" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
        fi
    fi
}

# ─── Banner ────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    echo "  ██████╗ ███████╗██╗███╗   ██╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo " ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo " ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo " ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo " ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${RESET}"
    echo -e "${GRAY}  OSINT Recon Tool v1.1 | Bash Edition | Solo para uso ético${RESET}"
    echo -e "${GRAY}  $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"
}

# ─── Ayuda ─────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Uso:${RESET}"
    echo -e "  $0 -t <dominio> [módulos] [opciones]\n"
    echo -e "${BOLD}Módulos:${RESET}"
    echo -e "  --whois         Información WHOIS del dominio"
    echo -e "  --dns           Registros DNS (A, MX, TXT, CNAME, NS)"
    echo -e "  --ip            Geolocalización e info de la IP"
    echo -e "  --headers       Cabeceras HTTP + análisis de seguridad"
    echo -e "  --robots        Contenido de robots.txt y sitemap.xml"
    echo -e "  --emails        Búsqueda de emails expuestos"
    echo -e "  --subdomains    Enumeración de subdominios"
    echo -e "  --ports         Escaneo de puertos comunes"
    echo -e "  --lookup        Buscar registro de email/teléfono en plataformas (usar con -l)"
    echo -e "  --all           Ejecutar todos los módulos\n"
    echo -e "${BOLD}Opciones:${RESET}"
    echo -e "  -t, --target    Dominio objetivo (requerido)"
    echo -e "  -o, --output    Guardar resultados en archivo"
    echo -e "  -l, --lookup-input  Email o teléfono a investigar (usado con --lookup)
  -w, --wordlist  Wordlist personalizada para subdominios"
    echo -e "  -h, --help      Mostrar esta ayuda\n"
    echo -e "${BOLD}Ejemplos:${RESET}"
    echo -e "  $0 -t ejemplo.com --all"
    echo -e "  $0 -t ejemplo.com --whois --dns --ip"
    echo -e "  $0 -t ejemplo.com --subdomains -w /usr/share/wordlists/subdomains.txt"
    echo -e "  $0 -t ejemplo.com --all -o reporte.txt
  $0 -t ejemplo.com --lookup -l correo@ejemplo.com
  $0 -t ejemplo.com --lookup -l +34612345678\n"
}

# ─── Helpers ───────────────────────────────────────────────────
print_section() {
    echo -e "\n${BOLD}${CYAN}$(printf '─%.0s' {1..55})${RESET}"
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    echo -e "${BOLD}${CYAN}$(printf '─%.0s' {1..55})${RESET}"
}

print_ok()   { echo -e "  ${GREEN}[+]${RESET} $1"; }
print_info() { echo -e "  ${YELLOW}[*]${RESET} $1"; }
print_err()  { echo -e "  ${RED}[-]${RESET} $1"; }
print_data() { printf "  ${GRAY}%-25s${RESET} ${BOLD}%s${RESET}\n" "$1" "$2"; }

log_result() {
    RESULTS+=("$1")
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "$1" >> "$OUTPUT_FILE"
    fi
}

# Verificar si un comando existe
check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        print_err "Comando '$1' no encontrado. Instala con: $2"
        return 1
    fi
    return 0
}

# ─── Módulo WHOIS ──────────────────────────────────────────────
module_whois() {
    print_section "WHOIS"

    check_cmd "whois" "sudo apt install whois" || return

    # Si es IP, hacer WHOIS de la IP directamente
    local whois_target="$TARGET"
    if $IS_IP; then
        print_info "Target es una IP — haciendo WHOIS de IP"
        whois_target="$TARGET_IP"
    fi

    local data
    data=$(whois "$whois_target" 2>/dev/null)

    if [[ -z "$data" ]]; then
        print_err "No se obtuvo respuesta WHOIS"
        return
    fi

    if $IS_IP; then
        # Para IPs los campos son distintos
        local ip_fields=(
            "NetName" "NetRange" "CIDR" "OrgName" "OrgId"
            "Country" "StateProv" "City" "PostalCode"
            "OrgAbuseEmail" "OrgTechEmail" "Comment"
        )
        for field in "${ip_fields[@]}"; do
            local value
            value=$(echo "$data" | grep -i "^$field:" | head -1 | cut -d':' -f2- | xargs)
            if [[ -n "$value" ]]; then
                print_data "$field" "$value"
                log_result "[WHOIS] $field: $value"
            fi
        done
        # Fallback por si los campos tienen otro formato (RIPE, LACNIC, etc.)
        if ! echo "$data" | grep -qi "^NetName:\|^OrgName:"; then
            local alt_fields=("inetnum" "netname" "descr" "country" "org" "mnt-by" "abuse-mailbox")
            for field in "${alt_fields[@]}"; do
                local value
                value=$(echo "$data" | grep -i "^$field:" | head -1 | cut -d':' -f2- | xargs)
                if [[ -n "$value" ]]; then
                    print_data "$field" "$value"
                    log_result "[WHOIS] $field: $value"
                fi
            done
        fi
    else
        local fields=(
            "Domain Name" "Registrar" "Creation Date" "Updated Date"
            "Registry Expiry Date" "Name Server" "Registrant Organization"
            "Registrant Country" "Registrant Email" "Admin Email" "Tech Email"
        )
        for field in "${fields[@]}"; do
            local value
            value=$(echo "$data" | grep -i "^$field:" | head -1 | cut -d':' -f2- | xargs)
            if [[ -n "$value" ]]; then
                print_data "$field" "$value"
                log_result "[WHOIS] $field: $value"
            fi
        done
    fi
}

# ─── Módulo DNS ────────────────────────────────────────────────
module_dns() {
    print_section "DNS Records"

    if $IS_IP; then
        print_info "Target es una IP — haciendo solo Reverse DNS"
        local rdns
        rdns=$(dig +short -x "$TARGET_IP" 2>/dev/null)
        if [[ -n "$rdns" ]]; then
            print_data "Reverse DNS (PTR)" "$rdns"
            log_result "[DNS] PTR: $rdns"
            print_info "Dominio encontrado: $rdns — puedes usarlo como target para --dns"
        else
            print_err "No hay registro PTR para $TARGET_IP (normal en IPs privadas/laboratorio)"
        fi
        return
    fi

    check_cmd "dig" "sudo apt install dnsutils" || return

    local types=("A" "AAAA" "MX" "TXT" "CNAME" "NS" "SOA")

    for type in "${types[@]}"; do
        local result
        result=$(dig +short "$type" "$TARGET" 2>/dev/null)
        if [[ -n "$result" ]]; then
            while IFS= read -r line; do
                print_data "$type" "$line"
                log_result "[DNS] $type: $line"
            done <<< "$result"
        fi
    done

    # Zone transfer attempt
    print_info "Intentando transferencia de zona (AXFR)..."
    local ns
    ns=$(dig +short NS "$TARGET" 2>/dev/null | head -1)
    if [[ -n "$ns" ]]; then
        local axfr
        axfr=$(dig AXFR "@$ns" "$TARGET" 2>/dev/null)
        if echo "$axfr" | grep -q "Transfer failed\|timed out\|connection refused" || [[ -z "$axfr" ]]; then
            print_err "AXFR denegado en $ns (correcto, el servidor está bien configurado)"
        else
            print_ok "AXFR exitoso en $ns — ¡posible misconfiguration!"
            echo "$axfr" | head -20
            log_result "[DNS] AXFR exitoso en $ns"
        fi
    fi
}

# ─── Módulo IP ─────────────────────────────────────────────────
module_ip() {
    print_section "Información de IP"

    # Si es IP local/privada, avisar y mostrar info básica
    local ip="$TARGET_IP"

    if [[ -z "$ip" ]]; then
        print_err "No se pudo resolver la IP de $TARGET"
        return
    fi

    if $IS_IP; then
        print_data "IP objetivo" "$ip"
    else
        print_data "Dominio" "$TARGET"
        print_data "IP resuelta" "$ip"
    fi
    log_result "[IP] $TARGET -> $ip"

    # Detectar si es IP privada
    if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        print_info "IP privada/local detectada — sin geolocalización disponible"
        print_info "Rango privado: red interna o laboratorio"
        log_result "[IP] Red privada: $ip"

        # Info de red local útil
        print_info "Información de red local:"
        if command -v arp &>/dev/null; then
            local mac
            mac=$(arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}')
            [[ -n "$mac" ]] && print_data "MAC Address" "$mac" && log_result "[IP] MAC: $mac"
        fi
        return
    fi

    # Geolocalización con ip-api.com (solo IPs públicas)
    print_info "Consultando geolocalización..."
    local geo
    geo=$(curl -s --max-time 8 "http://ip-api.com/json/$ip?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,hosting" 2>/dev/null)

    if [[ -n "$geo" ]]; then
        local fields=("country" "countryCode" "regionName" "city" "zip" "lat" "lon" "isp" "org" "as" "hosting")
        local labels=("País" "Código país" "Región" "Ciudad" "C. Postal" "Latitud" "Longitud" "ISP" "Organización" "ASN" "¿Hosting?")

        for i in "${!fields[@]}"; do
            local val
            val=$(echo "$geo" | grep -o "\"${fields[$i]}\":[^,}]*" | cut -d':' -f2- | tr -d '"' | xargs)
            if [[ -n "$val" && "$val" != "false" && "$val" != "true" ]]; then
                print_data "${labels[$i]}" "$val"
                log_result "[IP-GEO] ${labels[$i]}: $val"
            elif [[ "$val" == "true" ]]; then
                print_data "${labels[$i]}" "Sí (posible VPS/CDN)"
                log_result "[IP-GEO] ${labels[$i]}: Sí"
            fi
        done
    fi

    # Reverse DNS
    local rdns
    rdns=$(dig +short -x "$ip" 2>/dev/null | head -1)
    if [[ -n "$rdns" ]]; then
        print_data "Reverse DNS" "$rdns"
        log_result "[IP] Reverse DNS: $rdns"
    else
        print_data "Reverse DNS" "No disponible"
    fi
}

# ─── Módulo Headers HTTP ───────────────────────────────────────
module_headers() {
    print_section "Cabeceras HTTP"

    check_cmd "curl" "sudo apt install curl" || return

    local url=""
    for scheme in "https" "http"; do
        local test_url="${scheme}://${TARGET}"
        local status
        status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$test_url" 2>/dev/null)
        if [[ "$status" =~ ^[23] ]]; then
            url="$test_url"
            break
        fi
    done

    if [[ -z "$url" ]]; then
        url="https://$TARGET"
    fi

    print_info "URL: $url"

    local headers
    headers=$(curl -skI --max-time 10 -A "Mozilla/5.0" -L "$url" 2>/dev/null)

    if [[ -z "$headers" ]]; then
        print_err "No se pudieron obtener cabeceras"
        return
    fi

    # Mostrar todas las cabeceras
    echo ""
    while IFS= read -r line; do
        if [[ "$line" =~ ^HTTP ]]; then
            print_ok "${BOLD}$line${RESET}"
        elif [[ -n "$line" ]]; then
            local key val
            key=$(echo "$line" | cut -d':' -f1)
            val=$(echo "$line" | cut -d':' -f2- | xargs)
            print_data "$key" "$val"
            log_result "[HEADERS] $key: $val"
        fi
    done <<< "$headers"

    # Análisis de seguridad
    echo -e "\n  ${BOLD}Análisis de cabeceras de seguridad:${RESET}"
    local sec_headers=(
        "Strict-Transport-Security:HSTS"
        "Content-Security-Policy:CSP"
        "X-Frame-Options:Clickjacking Protection"
        "X-Content-Type-Options:MIME Sniffing Protection"
        "X-XSS-Protection:XSS Filter"
        "Referrer-Policy:Referrer Policy"
        "Permissions-Policy:Permissions Policy"
    )

    for entry in "${sec_headers[@]}"; do
        local header label
        header=$(echo "$entry" | cut -d':' -f1)
        label=$(echo "$entry" | cut -d':' -f2)
        if echo "$headers" | grep -qi "^$header:"; then
            print_ok "${GREEN}$label presente${RESET}"
        else
            print_err "${RED}$label ausente${RESET} — posible vector"
        fi
    done

    # Tecnologías detectadas
    echo -e "\n  ${BOLD}Tecnologías detectadas:${RESET}"
    local tech_headers=("Server" "X-Powered-By" "X-Generator" "X-AspNet-Version" "X-AspNetMvc-Version" "Via" "CF-Ray")
    for h in "${tech_headers[@]}"; do
        local val
        val=$(echo "$headers" | grep -i "^$h:" | head -1 | cut -d':' -f2- | xargs)
        if [[ -n "$val" ]]; then
            print_ok "${YELLOW}$h:${RESET} $val"
            log_result "[HEADERS-TECH] $h: $val"
        fi
    done
}

# ─── Módulo Robots & Sitemap ───────────────────────────────────
module_robots() {
    print_section "Robots.txt / Sitemap / Archivos sensibles"

    check_cmd "curl" "sudo apt install curl" || return

    local paths=(
        "/robots.txt"
        "/sitemap.xml"
        "/sitemap_index.xml"
        "/.well-known/security.txt"
        "/crossdomain.xml"
        "/humans.txt"
        "/.htaccess"
        "/web.config"
        "/phpinfo.php"
        "/.env"
        "/config.php"
        "/wp-login.php"
        "/admin"
        "/administrator"
        "/login"
        "/panel"
    )

    for scheme in "https" "http"; do
        local base="${scheme}://${TARGET}"
        for path in "${paths[@]}"; do
            local url="${base}${path}"
            local status
            status=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 -A "Mozilla/5.0" "$url" 2>/dev/null)

            case "$status" in
                200)
                    print_ok "${GREEN}[200]${RESET} $url"
                    log_result "[ROBOTS/FILES] 200 - $url"
                    # Mostrar contenido de robots.txt
                    if [[ "$path" == "/robots.txt" || "$path" == "/sitemap.xml" ]]; then
                        echo -e "\n${GRAY}$(printf '─%.0s' {1..50})${RESET}"
                        curl -sk --max-time 6 -A "Mozilla/5.0" "$url" 2>/dev/null | head -30 | while IFS= read -r line; do
                            echo -e "  ${GRAY}$line${RESET}"
                        done
                        echo -e "${GRAY}$(printf '─%.0s' {1..50})${RESET}\n"
                    fi
                    ;;
                301|302|303|307|308)
                    print_info "${YELLOW}[$status]${RESET} $url (redirección)"
                    ;;
                403)
                    print_info "${YELLOW}[403]${RESET} $url (prohibido — existe pero sin acceso)"
                    log_result "[ROBOTS/FILES] 403 - $url"
                    ;;
            esac
        done
        break
    done
}

# ─── Módulo Emails ─────────────────────────────────────────────
module_emails() {
    print_section "Búsqueda de Emails Expuestos"

    check_cmd "curl" "sudo apt install curl" || return
    check_cmd "grep" "" || return

    local pages=("" "/contact" "/about" "/team" "/contacto" "/equipo" "/acerca" "/support")
    local found_emails=()

    for scheme in "https" "http"; do
        for page in "${pages[@]}"; do
            local url="${scheme}://${TARGET}${page}"
            local content
            content=$(curl -skL --max-time 8 -A "Mozilla/5.0" "$url" 2>/dev/null)

            if [[ -n "$content" ]]; then
                # Extraer emails con grep
                local emails
                emails=$(echo "$content" | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' | \
                         grep -v -E '\.(png|jpg|gif|css|js|svg|ico|woff)' | sort -u)

                while IFS= read -r email; do
                    if [[ -n "$email" ]] && [[ ! " ${found_emails[*]} " =~ " ${email} " ]]; then
                        found_emails+=("$email")
                        print_ok "${GREEN}$email${RESET}"
                        log_result "[EMAILS] $email"
                    fi
                done <<< "$emails"
            fi
        done
        break
    done

    if [[ ${#found_emails[@]} -eq 0 ]]; then
        print_err "No se encontraron emails expuestos"
    else
        print_info "Total encontrados: ${#found_emails[@]}"
    fi

    print_info "Para búsqueda avanzada: theHarvester -d $TARGET -b all"
}

# ─── Módulo Subdominios ────────────────────────────────────────
module_subdomains() {
    print_section "Enumeración de Subdominios"

    if $IS_IP; then
        print_err "Los subdominios no aplican a IPs directas"
        print_info "Tip: Si conoces el dominio de esta máquina, úsalo como target"
        print_info "     Ejemplo: ./osint_recon.sh -t ejemplo.com --subdomains"
        return
    fi

    check_cmd "dig" "sudo apt install dnsutils" || return

    local wordlist_arr=(
        www mail ftp smtp pop imap webmail admin portal vpn remote
        dev staging test api cdn static media blog shop store app
        mx ns1 ns2 dns git gitlab jenkins jira confluence wiki
        intranet extranet proxy monitor dashboard panel cpanel whm
        plesk support helpdesk status cloud assets img images
        beta alpha old backup db database mysql phpmyadmin
        ssh sftp ldap radius ntp syslog nagios zabbix grafana
        kibana elasticsearch redis mongo postgres
    )

    local found=0

    if [[ -n "$WORDLIST" && -f "$WORDLIST" ]]; then
        print_info "Wordlist: $WORDLIST ($(wc -l < "$WORDLIST") entradas)"
        while IFS= read -r sub; do
            [[ -z "$sub" || "$sub" =~ ^# ]] && continue
            local full="${sub}.${TARGET}"
            local ip
            ip=$(dig +short A "$full" 2>/dev/null | head -1)
            if [[ -n "$ip" ]]; then
                printf "  ${GREEN}[+]${RESET} %-45s ${BOLD}→ %s${RESET}\n" "$full" "$ip"
                log_result "[SUBDOMAINS] $full -> $ip"
                ((found++))
            fi
        done < "$WORDLIST"
    else
        print_info "Wordlist interna: ${#wordlist_arr[@]} entradas"
        for sub in "${wordlist_arr[@]}"; do
            local full="${sub}.${TARGET}"
            local ip
            ip=$(dig +short A "$full" 2>/dev/null | head -1)
            if [[ -n "$ip" ]]; then
                printf "  ${GREEN}[+]${RESET} %-45s ${BOLD}→ %s${RESET}\n" "$full" "$ip"
                log_result "[SUBDOMAINS] $full -> $ip"
                ((found++))
            fi
        done
    fi

    if [[ $found -eq 0 ]]; then
        print_err "No se encontraron subdominios activos"
    else
        print_info "Total encontrados: $found"
    fi

    print_info "Para mayor cobertura: gobuster dns -d $TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
}

# ─── Módulo Puertos ────────────────────────────────────────────
module_ports() {
    print_section "Escaneo de Puertos Comunes"

    local ip="$TARGET_IP"

    if [[ -z "$ip" ]]; then
        print_err "No se pudo obtener la IP de $TARGET"
        return
    fi

    print_info "IP objetivo: $ip"

    declare -A PORTS=(
        [21]="FTP"      [22]="SSH"       [23]="Telnet"
        [25]="SMTP"     [53]="DNS"       [80]="HTTP"
        [110]="POP3"    [143]="IMAP"     [443]="HTTPS"
        [445]="SMB"     [512]="rexec"    [513]="rlogin"
        [514]="rsh"     [1099]="RMI"     [1524]="Metasploit"
        [2049]="NFS"    [3306]="MySQL"   [3389]="RDP"
        [5432]="PostgreSQL" [5900]="VNC" [6379]="Redis"
        [6667]="IRC"    [8009]="AJP"     [8080]="HTTP-Alt"
        [8443]="HTTPS-Alt" [8888]="HTTP-Alt" [27017]="MongoDB"
    )

    if command -v nmap &>/dev/null; then
        print_info "Usando nmap..."
        local ports_list
        ports_list=$(IFS=,; echo "${!PORTS[*]}")
        local nmap_out
        nmap_out=$(nmap -sV -T4 --open -p "$ports_list" "$ip" 2>/dev/null)

        echo "$nmap_out" | while IFS= read -r line; do
            if echo "$line" | grep -q "open"; then
                print_ok "$line"
                log_result "[PORTS] $line"
            fi
        done

        # Resumen de OS si está disponible
        local os_info
        os_info=$(echo "$nmap_out" | grep "OS details\|Running:" | head -1)
        [[ -n "$os_info" ]] && print_info "Sistema: $os_info"

    else
        print_info "Nmap no disponible — usando /dev/tcp (más lento)..."
        for port in $(echo "${!PORTS[@]}" | tr ' ' '\n' | sort -n); do
            local service="${PORTS[$port]}"
            if (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null; then
                print_ok "${GREEN}$port/tcp OPEN${RESET} — $service"
                log_result "[PORTS] $port/tcp open - $service"
            fi
        done
    fi
}

# ─── Guardar reporte ───────────────────────────────────────────

# ─── Módulo Lookup (Email / Teléfono → Plataformas) ───────────
module_lookup() {
    print_section "Búsqueda de Email / Teléfono en Plataformas"

    check_cmd "curl"  "sudo apt install curl"  || return
    check_cmd "grep"  ""                        || return

    local input="$LOOKUP_INPUT"

    if [[ -z "$input" ]]; then
        print_err "Debes indicar un email o teléfono con -l <valor>"
        return
    fi

    # ── Detectar tipo de input ─────────────────────────────────
    local IS_EMAIL=false
    local IS_PHONE=false
    local phone_clean=""

    if [[ "$input" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then
        IS_EMAIL=true
        print_info "Tipo detectado: EMAIL → $input"
        log_result "[LOOKUP] Tipo: Email - $input"
    elif [[ "$input" =~ ^[\+]?[0-9\ \-\(\)]{7,20}$ ]]; then
        IS_PHONE=true
        phone_clean=$(echo "$input" | tr -d ' ()-')
        print_info "Tipo detectado: TELÉFONO → $phone_clean"
        log_result "[LOOKUP] Tipo: Teléfono - $phone_clean"
    else
        print_err "Formato no reconocido. Usa un email válido o teléfono (ej: +34612345678)"
        return
    fi

    # ══════════════════════════════════════════════════════════
    #  SECCIÓN EMAIL
    # ══════════════════════════════════════════════════════════
    if $IS_EMAIL; then

        echo -e "\n  ${BOLD}[1] HaveIBeenPwned — Brechas de datos${RESET}"
        local hibp_resp
        hibp_resp=$(curl -sL --max-time 10 \
            -H "User-Agent: osint-recon-tool" \
            -H "hibp-api-key: " \
            "https://haveibeenpwned.com/api/v3/breachedaccount/${input}?truncateResponse=false" 2>/dev/null)

        if echo "$hibp_resp" | grep -q "Name"; then
            local breaches
            breaches=$(echo "$hibp_resp" | grep -oP '"Name":"\K[^"]+')
            while IFS= read -r b; do
                print_ok "Brecha encontrada: ${YELLOW}$b${RESET}"
                log_result "[LOOKUP-HIBP] Brecha: $b"
            done <<< "$breaches"
        elif echo "$hibp_resp" | grep -qi "unauthorised\|unauthorized"; then
            print_info "HIBP requiere API key (https://haveibeenpwned.com/API/Key)"
            print_info "Visita manualmente: https://haveibeenpwned.com/account/$input"
        else
            print_ok "No se encontraron brechas conocidas en HIBP"
        fi

        echo -e "\n  ${BOLD}[2] Registro en redes sociales y plataformas populares${RESET}"
        print_info "Comprobando existencia de cuenta por respuesta HTTP..."

        # Plataformas que permiten verificar por email vía API/formulario público
        declare -A PLATFORM_CHECKS=(
            ["Gravatar"]="https://en.gravatar.com/$(echo -n "$input" | md5sum | awk '{print $1}').json"
            ["Adobe"]="https://auth.services.adobe.com/en_US/index.html#from=DEJAVU&it=true&destination=https://account.adobe.com/&redirectUrl=https://account.adobe.com/"
        )

        # Gravatar (devuelve 200 si existe cuenta)
        local grav_hash
        grav_hash=$(echo -n "$input" | tr '[:upper:]' '[:lower:]' | md5sum | awk '{print $1}')
        local grav_url="https://en.gravatar.com/${grav_hash}.json"
        local grav_status
        grav_status=$(curl -so /dev/null -w "%{http_code}" --max-time 6 "$grav_url" 2>/dev/null)
        if [[ "$grav_status" == "200" ]]; then
            local grav_data
            grav_data=$(curl -sL --max-time 6 "$grav_url" 2>/dev/null)
            local grav_user
            grav_user=$(echo "$grav_data" | grep -oP '"preferredUsername":"\K[^"]+' | head -1)
            print_ok "${GREEN}Gravatar${RESET} → Cuenta encontrada${grav_user:+ (usuario: $grav_user)}"
            log_result "[LOOKUP] Gravatar: encontrado${grav_user:+ - $grav_user}"
        else
            print_err "Gravatar → No encontrado"
        fi

        echo -e "\n  ${BOLD}[3] Verificación en servicios de autenticación${RESET}"

        # Firefox Accounts
        local ff_resp
        ff_resp=$(curl -sL --max-time 8 \
            -X POST "https://api.accounts.firefox.com/v1/account/status" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$input\"}" 2>/dev/null)
        if echo "$ff_resp" | grep -q '"exists":true'; then
            print_ok "${GREEN}Firefox Accounts (Mozilla)${RESET} → Cuenta registrada"
            log_result "[LOOKUP] Firefox Accounts: encontrado"
        elif echo "$ff_resp" | grep -q '"exists":false'; then
            print_err "Firefox Accounts (Mozilla) → No encontrado"
        else
            print_info "Firefox Accounts → Sin respuesta definitiva"
        fi

        # Proton Mail
        local proton_resp
        proton_resp=$(curl -sL --max-time 8 \
            "https://account.proton.me/api/core/v4/users/available?Name=${input%%@*}" \
            -H "x-pm-appversion: web-account@5.0.99.0" 2>/dev/null)
        if echo "$proton_resp" | grep -q '"Code":12011\|not available\|already'; then
            print_ok "${GREEN}Proton Mail${RESET} → Nombre de usuario/email en uso"
            log_result "[LOOKUP] Proton Mail: posiblemente registrado"
        else
            print_err "Proton Mail → No detectado (o nombre disponible)"
        fi

        echo -e "\n  ${BOLD}[4] Búsqueda OSINT en motores de búsqueda (dorks)${RESET}"
        local encoded_email
        encoded_email=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$input'))" 2>/dev/null || echo "$input")
        print_info "Google dork:    https://www.google.com/search?q=%22$encoded_email%22"
        print_info "Bing dork:      https://www.bing.com/search?q=%22$encoded_email%22"
        print_info "HIBP manual:    https://haveibeenpwned.com/account/$input"
        print_info "Dehashed:       https://dehashed.com/search?query=$input"
        print_info "IntelX:         https://intelx.io/?s=$input"
        print_info "Hunter.io:      https://hunter.io/email-verifier/$input"
        print_info "EmailRep:       https://emailrep.io/$input"
        log_result "[LOOKUP] Dorks generados para: $input"

        echo -e "\n  ${BOLD}[5] EmailRep.io — Reputación del email${RESET}"
        local emailrep_resp
        emailrep_resp=$(curl -sL --max-time 10 \
            -H "User-Agent: osint-recon-tool" \
            "https://emailrep.io/$input" 2>/dev/null)
        if [[ -n "$emailrep_resp" ]] && echo "$emailrep_resp" | grep -q '"reputation"'; then
            local rep_score rep_suspicious rep_profiles
            rep_score=$(echo "$emailrep_resp" | grep -oP '"reputation":"\K[^"]+')
            rep_suspicious=$(echo "$emailrep_resp" | grep -oP '"suspicious":\K(true|false)')
            rep_profiles=$(echo "$emailrep_resp" | grep -oP '"profiles":\[([^\]]*)\]' | grep -oP '"[a-z0-9_]+"' | tr -d '"' | tr '\n' ' ')
            [[ -n "$rep_score" ]]     && print_data "Reputación"   "$rep_score"  && log_result "[LOOKUP-EMAILREP] Reputación: $rep_score"
            [[ -n "$rep_suspicious" ]] && print_data "Sospechoso"  "$rep_suspicious" && log_result "[LOOKUP-EMAILREP] Sospechoso: $rep_suspicious"
            [[ -n "$rep_profiles" ]]  && print_data "Perfiles"     "$rep_profiles" && log_result "[LOOKUP-EMAILREP] Perfiles: $rep_profiles"
        else
            print_info "EmailRep sin respuesta — puede requerir API key o límite alcanzado"
        fi

    fi

    # ══════════════════════════════════════════════════════════
    #  SECCIÓN TELÉFONO
    # ══════════════════════════════════════════════════════════
    if $IS_PHONE; then

        echo -e "\n  ${BOLD}[1] Geolocalización e info del número${RESET}"
        local numverify_resp
        numverify_resp=$(curl -sL --max-time 8 \
            "http://apilayer.net/api/validate?access_key=&number=${phone_clean}&format=1" 2>/dev/null)
        if echo "$numverify_resp" | grep -q '"valid":true'; then
            local nv_country nv_location nv_carrier nv_line
            nv_country=$(echo "$numverify_resp"  | grep -oP '"country_name":"\K[^"]+')
            nv_location=$(echo "$numverify_resp" | grep -oP '"location":"\K[^"]+')
            nv_carrier=$(echo "$numverify_resp"  | grep -oP '"carrier":"\K[^"]+')
            nv_line=$(echo "$numverify_resp"     | grep -oP '"line_type":"\K[^"]+')
            print_ok "Número válido"
            [[ -n "$nv_country" ]]  && print_data "País"        "$nv_country"
            [[ -n "$nv_location" ]] && print_data "Localización" "$nv_location"
            [[ -n "$nv_carrier" ]]  && print_data "Operadora"   "$nv_carrier"
            [[ -n "$nv_line" ]]     && print_data "Tipo de línea" "$nv_line"
            log_result "[LOOKUP-PHONE] Válido | País: $nv_country | Operadora: $nv_carrier"
        else
            print_info "Numverify sin respuesta (requiere API key gratuita en numverify.com)"
        fi

        echo -e "\n  ${BOLD}[2] Búsqueda en directorios de teléfonos${RESET}"
        local phone_encoded
        phone_encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$phone_clean'))" 2>/dev/null || echo "$phone_clean")
        print_info "TrueCaller (manual): https://www.truecaller.com/search/es/$phone_encoded"
        print_info "NumLookup:           https://www.numlookup.com/phone-lookup/$phone_clean"
        print_info "PhoneInfoga:         https://demo.phoneinfoga.crvx.fr/#/$phone_clean/scan"
        print_info "Google dork:         https://www.google.com/search?q=%22$phone_clean%22"
        print_info "Sync.me:             https://sync.me/search/?number=$phone_clean"
        log_result "[LOOKUP-PHONE] Dorks generados para: $phone_clean"

        echo -e "\n  ${BOLD}[3] Comprobación de WhatsApp${RESET}"
        # Técnica: intentar abrir chat de WhatsApp (no confirmación directa, solo referencia)
        print_info "Enlace directo WhatsApp: https://wa.me/$phone_clean"
        print_info "Si abre chat → el número tiene WhatsApp activo"
        log_result "[LOOKUP-PHONE] WhatsApp: https://wa.me/$phone_clean"

        echo -e "\n  ${BOLD}[4] Registro en plataformas (verificación por formulario)${RESET}"
        print_info "Telegram:    https://t.me/+$phone_clean (si redirige a perfil → cuenta activa)"
        print_info "Snapchat:    https://accounts.snapchat.com/accounts/password_reset_request"
        print_info "Signal:      No tiene buscador público — requiere tenerlo en agenda"
        print_info "Twitter/X:   https://twitter.com/i/flow/login (usa 'olvidé contraseña' → introducir número)"
        print_info "Instagram:   https://www.instagram.com/accounts/password/reset/ (mismo método)"
        print_info "Facebook:    https://www.facebook.com/login/identify/?ctx=recover (introducir número)"
        log_result "[LOOKUP-PHONE] Plataformas verificadas manualmente"

        echo -e "\n  ${BOLD}[5] Herramientas adicionales recomendadas${RESET}"
        print_info "PhoneInfoga (local): pip install phoneinfoga && phoneinfoga scan -n $phone_clean"
        print_info "Ignorant (pip):      pip install ignorant && ignorant phone $phone_clean"
        log_result "[LOOKUP-PHONE] Herramientas externas sugeridas"

    fi

    # ══════════════════════════════════════════════════════════
    #  COMUNES A AMBOS
    # ══════════════════════════════════════════════════════════
    echo -e "\n  ${BOLD}[+] Herramientas externas recomendadas${RESET}"
    if $IS_EMAIL; then
        print_info "theHarvester:   theHarvester -d ${input##*@} -b all"
        print_info "h8mail:         h8mail -t $input"
        print_info "Holehe:         holehe $input  (comprueba 120+ plataformas)"
        print_info "Maigret:        maigret --email $input"
    fi
    if $IS_PHONE; then
        print_info "PhoneInfoga:    phoneinfoga scan -n $phone_clean"
        print_info "Ignorant:       ignorant phone $phone_clean"
        print_info "Sherlock:       sherlock (si conoces el username asociado)"
    fi
}

save_report() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "══════════════════════════════════════════════════════════════"
        echo "                    OSINT Recon Report"
        echo "══════════════════════════════════════════════════════════════"
        echo "  Objetivo : $TARGET"
        echo "  Fecha    : $timestamp"
        echo "══════════════════════════════════════════════════════════════"
        echo ""
        for line in "${RESULTS[@]}"; do
            echo "$line"
        done
    } > "$OUTPUT_FILE"

    print_ok "Reporte guardado en: ${BOLD}$OUTPUT_FILE${RESET}"
}

# ─── Parse de argumentos ───────────────────────────────────────
parse_args() {
    if [[ $# -eq 0 ]]; then
        banner
        usage
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)     TARGET="$2"; shift 2 ;;
            -o|--output)     OUTPUT_FILE="$2"; shift 2 ;;
            -l|--lookup-input) LOOKUP_INPUT="$2"; shift 2 ;;
            -w|--wordlist)   WORDLIST="$2"; shift 2 ;;
            --whois)         MOD_WHOIS=true; shift ;;
            --dns)           MOD_DNS=true; shift ;;
            --ip)            MOD_IP=true; shift ;;
            --headers)       MOD_HEADERS=true; shift ;;
            --robots)        MOD_ROBOTS=true; shift ;;
            --emails)        MOD_EMAILS=true; shift ;;
            --subdomains)    MOD_SUBDOMAINS=true; shift ;;
            --ports)         MOD_PORTS=true; shift ;;
            --lookup)        MOD_LOOKUP=true; shift ;;
            --all)           RUN_ALL=true; shift ;;
            -h|--help)       banner; usage; exit 0 ;;
            *)               echo -e "${RED}[!] Argumento desconocido: $1${RESET}"; usage; exit 1 ;;
        esac
    done

    # Target obligatorio
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] Debes especificar un objetivo con -t <dominio>${RESET}\n"
        usage
        exit 1
    fi

    # Limpiar target
    TARGET=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')

    # Si no se eligió ningún módulo
    if ! $RUN_ALL && ! $MOD_WHOIS && ! $MOD_DNS && ! $MOD_IP && \
       ! $MOD_HEADERS && ! $MOD_ROBOTS && ! $MOD_EMAILS && \
       ! $MOD_SUBDOMAINS && ! $MOD_PORTS && ! $MOD_LOOKUP; then
        echo -e "${RED}[!] Debes seleccionar al menos un módulo o usar --all${RESET}\n"
        usage
        exit 1
    fi
}

# ─── Main ──────────────────────────────────────────────────────
main() {
    parse_args "$@"
    banner

    echo -e "  ${BOLD}Objetivo:${RESET} ${CYAN}$TARGET${RESET}"
    echo -e "  ${BOLD}Inicio:${RESET}   $(date '+%Y-%m-%d %H:%M:%S')\n"

    log_result "Objetivo: $TARGET"
    log_result "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"

    # Resolver IP del target una sola vez para todos los módulos
    resolve_target_ip

    if $IS_IP; then
        print_info "Modo: IP directa ($TARGET_IP)"
    else
        if [[ -n "$TARGET_IP" ]]; then
            print_info "IP resuelta: $TARGET_IP"
        else
            print_info "No se pudo resolver IP — algunos módulos pueden fallar"
        fi
    fi

    # Ejecutar módulos
    ($RUN_ALL || $MOD_WHOIS)      && module_whois
    ($RUN_ALL || $MOD_DNS)        && module_dns
    ($RUN_ALL || $MOD_IP)         && module_ip
    ($RUN_ALL || $MOD_HEADERS)    && module_headers
    ($RUN_ALL || $MOD_ROBOTS)     && module_robots
    ($RUN_ALL || $MOD_EMAILS)     && module_emails
    ($RUN_ALL || $MOD_PORTS)      && module_ports
    ($RUN_ALL || $MOD_SUBDOMAINS) && module_subdomains
    ($MOD_LOOKUP) && module_lookup

    # Guardar reporte si se pidió
    [[ -n "$OUTPUT_FILE" ]] && save_report

    echo -e "\n${CYAN}$(printf '─%.0s' {1..55})${RESET}"
    echo -e "  ${BOLD}Reconocimiento completado.${RESET}"
    echo -e "  ${GRAY}Solo para uso ético y en entornos autorizados.${RESET}\n"
}

main "$@"
