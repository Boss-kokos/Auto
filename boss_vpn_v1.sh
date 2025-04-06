#!/bin/bash
# =============================================================================
# Поддержка Ubuntu 20.04, 22.04, 24.04, Linux Mint (улучшенная версия)
# Версия: 2.5.1 
# =============================================================================

# Проверка наличия root-прав
if [ "$EUID" -ne 0 ]; then
  echo "Ошибка: скрипт должен запускаться от пользователя root." >&2
  exit 1
fi

# Установка неинтерактивного режима для apt (чтобы apt не ждал ввода)
export DEBIAN_FRONTEND=noninteractive

# Цветовые коды для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # сброс цвета

# Глобальные переменные для логирования шагов
STEP_LOG=()
SCRIPT_ERROR=0

# Функции логирования успешных и ошибочных шагов
log_info() {
    echo -e "${GREEN}[OK]${NC} $1"
    STEP_LOG+=("${GREEN}[OK]${NC} $1")
}
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    STEP_LOG+=("${RED}[ERROR]${NC} $1")
}

# Функция аварийного завершения с выводом лога шагов
error_exit() {
    log_error "$1"
    SCRIPT_ERROR=1
    echo -e "\n${YELLOW}Ход выполнения:${NC}"
    for step in "${STEP_LOG[@]}"; do
        echo -e "$step"
    done
    echo -e "\n[Завершение скрипта]"
    exit 1
}

# Функция установки требуемых пакетов (обновление системы)
install_packages() {
    log_info "Обновление списка пакетов и системы"
    apt-get update || error_exit "Не удалось выполнить apt update"
    apt-get upgrade -y || error_exit "Не удалось обновить систему"
    log_info "Система обновлена"

    # Формируем список пакетов для установки (без лишнего NetworkManager)
    packages="htop net-tools mtr wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server libapache2-mod-authnz-pam dos2unix python3-pip vnstat"
    # Добавляем пакет для venv соответствующей версии Python
    PY_VER=$(python3 -V 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
    packages+=" python3-venv"
    if apt-cache show "python${PY_VER}-venv" > /dev/null 2>&1; then
        packages+=" python${PY_VER}-venv"
    fi

    apt-get install -y $packages || error_exit "Не удалось установить необходимые пакеты"
    log_info "Необходимые системные пакеты установлены"

    # Включение необходимых модулей Apache (proxy, rewrite, pam-auth)
    a2enmod proxy || error_exit "Не удалось включить модуль Apache proxy"
    a2enmod proxy_http || error_exit "Не удалось включить модуль Apache proxy_http"
    a2enmod rewrite || error_exit "Не удалось включить модуль Apache rewrite"
    a2enmod authnz_pam || error_exit "Не удалось включить модуль Apache authnz_pam"
    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache после включения модулей"
    log_info "Модули Apache включены"

    # Удаление конфликтующих сервисов (dnsmasq, openvswitch), если присутствуют
    if dpkg -l | grep -qw dnsmasq; then
        log_info "Удаляется dnsmasq (конфликтующий DNS/DHCP)"
        systemctl stop dnsmasq 2>/dev/null
        systemctl disable dnsmasq 2>/dev/null
        apt-get purge -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dnsmasq || error_exit "Не удалось удалить dnsmasq"
        log_info "dnsmasq удалён"
    fi
    if dpkg -l | grep -qw openvswitch-switch; then
        log_info "Удаляется openvswitch-switch (не требуется)"
        systemctl stop openvswitch-switch 2>/dev/null
        systemctl disable openvswitch-switch 2>/dev/null
        apt-get purge -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" openvswitch-switch || error_exit "Не удалось удалить openvswitch-switch"
        log_info "openvswitch-switch удалён"
    fi
}

# Функция выбора сетевых интерфейсов (WAN и LAN)
select_interfaces() {
    echo -e "${GREEN}Получаю список сетевых интерфейсов...${NC}"
    all_interfaces=$(ip -o link show | awk '$2 != "lo:" {print $2}' | sed 's/://')
    full_list=""
    count=0
    for iface in $all_interfaces; do
        count=$((count+1))
        ip_addr=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1)
        if [ -z "$ip_addr" ]; then
            ip_addr="(нет IP)"
        fi
        full_list+="$count) $iface : $ip_addr\n"
        interfaces_array[$count]="$iface"
    done
    echo -e "Доступные сетевые интерфейсы:\n$full_list"
    echo ""
    read -r -p "Введите номер ВХОДЯЩЕГО интерфейса (интернет/WAN): " in_num
    IN_IF="${interfaces_array[$in_num]}"
    if [ -z "$IN_IF" ]; then
        error_exit "Некорректный выбор входящего интерфейса"
    fi
    read -r -p "Введите номер ВЫХОДЯЩЕГО интерфейса (локальная сеть/LAN): " out_num
    OUT_IF="${interfaces_array[$out_num]}"
    if [ -z "$OUT_IF" ]; then
        error_exit "Некорректный выбор выходящего интерфейса"
    fi
    log_info "Выбран входящий интерфейс: $IN_IF"
    log_info "Выбран выходящий интерфейс: $OUT_IF"
    read -r -p "Использовать стандартный локальный IP-адрес 192.168.1.1 для LAN? [y/n]: " use_default
    if [ "$use_default" == "n" ]; then
        read -r -p "Введите желаемый локальный IP-адрес (формат 192.168.X.1): " LOCAL_IP
        if [[ ! $LOCAL_IP =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
            error_exit "Неверный формат локального IP"
        fi
    else
        LOCAL_IP="192.168.1.1"
    fi
    log_info "Локальный адрес LAN будет: $LOCAL_IP"
}

# Настройка DNS через systemd-resolved (Google DNS по умолчанию)
configure_dns() {
    log_info "Настраиваю DNS через systemd-resolved"
    RESOLVED_CONF="/etc/systemd/resolved.conf"
    if grep -q "^\[Resolve\]" "$RESOLVED_CONF"; then
        sed -i '/^\[Resolve\]/,/^\[/ s/^DNS=.*//g' "$RESOLVED_CONF"
        sed -i '/^\[Resolve\]/a DNS=8.8.8.8 8.8.4.4' "$RESOLVED_CONF"
    else
        echo -e "\n[Resolve]\nDNS=8.8.8.8 8.8.4.4" >> "$RESOLVED_CONF"
    fi
    systemctl restart systemd-resolved || error_exit "Не удалось перезапустить systemd-resolved"
    log_info "DNS-серверы (8.8.8.8/8.8.4.4) настроены в systemd-resolved"
}

# Настройка DHCP-сервера (isc-dhcp-server) для локальной сети (LAN)
configure_dhcp() {
    log_info "Настраиваю DHCP-сервер (isc-dhcp-server)"
    DHCP_CONF="/etc/dhcp/dhcpd.conf"
    DHCP_DEFAULT="/etc/default/isc-dhcp-server"
    [ -f "$DHCP_CONF" ] && cp "$DHCP_CONF" "${DHCP_CONF}.bak"
    cat <<EOF > "$DHCP_CONF"
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet ${LOCAL_IP%.*}.0 netmask 255.255.255.0 {
    range ${LOCAL_IP%.*}.2 ${LOCAL_IP%.*}.254;
    option routers $LOCAL_IP;
    option subnet-mask 255.255.255.0;
    option domain-name "local.lan";
    option domain-name-servers 8.8.8.8, 8.8.4.4;
}
EOF
    if grep -q "^INTERFACESv4=" "$DHCP_DEFAULT"; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$OUT_IF\"/" "$DHCP_DEFAULT"
    else
        echo "INTERFACESv4=\"$OUT_IF\"" >> "$DHCP_DEFAULT"
    fi
    chown root:dhcpd /var/lib/dhcp/dhcpd.leases || error_exit "Не удалось применить chown root:dhcpd для dhcpd.leases"
    chmod 664 /var/lib/dhcp/dhcpd.leases || error_exit "Не удалось применить chmod 664 для dhcpd.leases"
    systemctl restart isc-dhcp-server || error_exit "Не удалось перезапустить isc-dhcp-server"
    systemctl enable isc-dhcp-server || error_exit "Не удалось включить isc-dhcp-server"
    log_info "DHCP-сервер isc-dhcp-server настроен и запущен"
}

# Настройка iptables и включение NAT (MASQUERADE) для трафика LAN->VPN
configure_iptables() {
    log_info "Настраиваю правила iptables (NAT)"
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
    sysctl -p || error_exit "Ошибка включения ip_forward через sysctl"
    iptables -t nat -A POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE || error_exit "Ошибка добавления правила MASQUERADE"
    iptables-save > /etc/iptables/rules.v4 || error_exit "Не удалось сохранить правила iptables"
    log_info "Правило MASQUERADE для ${LOCAL_IP%.*}.0/24 добавлено (через tun0)"
}

# Настройка OpenVPN (включение автозапуска всех конфигураций)
configure_vpn() {
    log_info "Настраиваю OpenVPN (включаю автозапуск конфигов)"
    sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn
    log_info "OpenVPN настроен (AUTOSTART=all)"
}

# Настройка веб-интерфейса (файлы, репозиторий, sudoers)
configure_web_interface() {
    log_info "Настраиваю файлы и доступ веб-интерфейса"
    chmod -R 755 /etc/openvpn /etc/wireguard
    chown -R www-data:www-data /etc/openvpn /etc/wireguard
    # Настройка привилегий sudo для веб-интерфейса (только необходимые команды вместо NOPASSWD:ALL)
    cat <<EOF > /etc/sudoers.d/vpn_admin
www-data ALL=(root) NOPASSWD: /usr/bin/arp-scan, /usr/bin/systemctl start openvpn@*, /usr/bin/systemctl stop openvpn@*, /usr/bin/systemctl restart openvpn@*, /usr/bin/systemctl start wg-quick@*, /usr/bin/systemctl stop wg-quick@*, /usr/bin/systemctl restart wg-quick@*
EOF
    chmod 440 /etc/sudoers.d/vpn_admin || error_exit "Не удалось установить права на /etc/sudoers.d/vpn_admin"
    rm -rf /var/www/html
    git clone https://github.com/Rostarc/web-cabinet.git /var/www/html || error_exit "Не удалось клонировать репозиторий web-cabinet"
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    log_info "Веб-интерфейс установлен в /var/www/html"
}

# Настройка виртуального хоста Apache и ограничение доступа (.htaccess)
configure_apache() {
    log_info "Настраиваю конфигурацию Apache (виртуальный хост и .htaccess)"
    cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    ProxyPass /shell/ http://127.0.0.1:4200/
    ProxyPassReverse /shell/ http://127.0.0.1:4200/

    <Directory "/var/www/html">
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>
</VirtualHost>
EOF
    log_info "Виртуальный хост Apache создан (000-default.conf)"
    cat <<'EOF' > /var/www/html/.htaccess
<RequireAll>
    Require ip 192.168
</RequireAll>

RewriteEngine On
RewriteBase /

# Исключаем каталог elfinder из перенаправлений
RewriteCond %{REQUEST_URI} ^/elfinder/ [NC]
RewriteRule .* - [L]

# Если запрошен существующий файл или каталог — не перенаправляем
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]

# Перенаправляем остальные запросы на index.php с параметром page
RewriteRule ^(.*)$ index.php?page=$1 [QSA,L]
EOF
    log_info ".htaccess создан (доступ ограничен локальной подсети 192.168.0.0/16)"
    sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf || error_exit "Не удалось изменить AllowOverride для /var/www/"
    log_info "AllowOverride All установлен для /var/www/ в apache2.conf"
    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache"
    log_info "Служба Apache перезапущена"
}

# Настройка сервиса Shell In A Box (веб-SSH)
configure_shellinabox() {
    log_info "Устанавливаю и настраиваю Shell In A Box"
    apt-get install -y shellinabox || error_exit "Не удалось установить shellinabox"
    systemctl enable shellinabox
    systemctl start shellinabox || error_exit "Не удалось запустить shellinabox"
    cat <<EOF > /etc/default/shellinabox
SHELLINABOX_DAEMON_START=1
SHELLINABOX_PORT=4200
SHELLINABOX_ARGS="--no-beep --disable-ssl"
EOF
    systemctl restart shellinabox || error_exit "Не удалось перезапустить shellinabox"
    log_info "Shell In A Box установлен и запущен (порт 4200, без SSL)"
}

# Настройка демона пинга и сбора системных метрик (ping_daemon.sh + service)
configure_ping_daemon() {
    log_info "Настраиваю демон сбора данных пинга и ресурсов"
    cat <<'EOF' > /usr/local/bin/ping_daemon.sh
#!/bin/bash
# Демон для сбора пинга (google.com) и системных метрик
PING_LOG="/var/log/ping_history.log"
SYS_STATS_LOG="/var/log/sys_stats.log"
HOST="google.com"
MAX_ENTRIES=86400
[ ! -f "$PING_LOG" ] && touch "$PING_LOG"
[ ! -f "$SYS_STATS_LOG" ] && touch "$SYS_STATS_LOG"
while true; do
  ping_output=$(ping -c 1 -w 5 "$HOST" 2>&1)
  ping_time=-1
  if [[ "$ping_output" =~ time=([0-9]+\.[0-9]+) ]]; then
    ping_time="${BASH_REMATCH[1]}"
  fi
  ts=$(date +%s)
  echo "$ts $ping_time" >> "$PING_LOG"
  if [ $(wc -l < "$PING_LOG") -gt "$MAX_ENTRIES" ]; then
    sed -i '1d' "$PING_LOG"
  fi
  cpu_line=$(top -b -n1 | grep "Cpu(s)")
  cpu_usage=0
  if [[ "$cpu_line" =~ ([0-9]+\.[0-9]+)[[:space:]]*us ]]; then
    cpu_usage="${BASH_REMATCH[1]}"
  fi
  free_output=$(free -m)
  ram_total=$(echo "$free_output" | awk '/Mem:/ {print $2}')
  ram_used=$(echo "$free_output" | awk '/Mem:/ {print $3}')
  ram_usage=0
  if [ "$ram_total" -gt 0 ]; then
    ram_usage=$(echo "scale=1; $ram_used*100/$ram_total" | bc)
  fi
  df_line=$(df -h / | tail -1)
  disk_perc=$(echo "$df_line" | awk '{print $5}' | sed 's/%//')
  echo "$ts $cpu_usage $ram_usage $disk_perc" >> "$SYS_STATS_LOG"
  if [ $(wc -l < "$SYS_STATS_LOG") -gt "$MAX_ENTRIES" ]; then
    sed -i '1d' "$SYS_STATS_LOG"
  fi
  sleep 2
done
EOF
    chmod +x /usr/local/bin/ping_daemon.sh || error_exit "Не удалось сделать ping_daemon.sh исполняемым"
    cat <<EOF > /etc/systemd/system/ping_daemon.service
[Unit]
Description=Ping Daemon (сбор ping каждые 2 секунды)
After=network.target

[Service]
ExecStart=/usr/local/bin/ping_daemon.sh
Restart=always
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || error_exit "Не удалось выполнить daemon-reload для ping_daemon.service"
    systemctl enable ping_daemon.service || error_exit "Не удалось включить ping_daemon.service"
    systemctl start ping_daemon.service || error_exit "Не удалось запустить ping_daemon.service"
    log_info "Сервис ping_daemon.service запущен (сбор пинга и метрик)"
}

# Настройка сервисов мониторинга сети и устройств (update_metrics, network_load)
configure_metrics_services() {
    log_info "Настраиваю сервисы мониторинга сети и устройств"
    cat <<EOF > /etc/systemd/system/update_metrics.service
[Unit]
Description=Update System Metrics Daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/update_metrics_daemon.py
Restart=always
RestartSec=10
User=www-data
Group=www-data
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=update-metrics

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || error_exit "Ошибка перезагрузки systemd для update_metrics.service"
    systemctl start update_metrics.service || error_exit "Не удалось запустить update_metrics.service"
    systemctl enable update_metrics.service || error_exit "Не удалось включить update_metrics.service"
    log_info "Сервис update_metrics.service включен"
    apt-get install -y arp-scan || error_exit "Не удалось установить arp-scan"
    mkdir -p /var/www/html/api
    cat <<'EOF' > /var/www/html/api/scan_local_network.py
#!/usr/bin/env python3
import subprocess, json, re, os
def scan_network(interface):
    try:
        result = subprocess.run(['sudo', 'arp-scan', '--interface=' + interface, '--localnet'],
                                capture_output=True, text=True, timeout=30)
        output = result.stdout
    except Exception as e:
        return {"error": str(e)}
    devices = []
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.*)')
    for line in output.splitlines():
        m = pattern.match(line)
        if m:
            ip = m.group(1); mac = m.group(2); vendor = m.group(3).strip()
            devices.append({"ip": ip, "mac": mac, "vendor": vendor})
    return {"devices": devices}
if __name__ == "__main__":
    interface = os.environ.get("OUT_IF", "enp0s8")
    data = scan_network(interface)
    output_file = "/var/www/html/data/local_network.json"
    with open(output_file, "w") as f:
        json.dump(data, f)
EOF
    chmod +x /var/www/html/api/scan_local_network.py || error_exit "Не удалось сделать scan_local_network.py исполняемым"
    # Добавляем задания в cron для сбора расширенных метрик каждую минуту и сканирования сети раз в 6 часов
    (crontab -u www-data -l 2>/dev/null; echo "* * * * * /usr/bin/python3 /var/www/html/api/update_network_metrics.py") | crontab -u www-data -
    (crontab -u www-data -l 2>/dev/null; echo "0 */6 * * * OUT_IF=${OUT_IF} /usr/bin/python3 /var/www/html/api/scan_local_network.py") | crontab -u www-data -
    # Сервис мониторинга сетевой загрузки (через psutil)
    cat <<EOF > /etc/systemd/system/network_load.service
[Unit]
Description=Network Load Monitor using psutil
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/update_network_load.py
WorkingDirectory=/var/www/html/api
User=www-data
Group=www-data
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=network-load

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || error_exit "Ошибка перезагрузки systemd для network_load.service"
    systemctl start network_load.service || error_exit "Не удалось запустить network_load.service"
    systemctl enable network_load.service || error_exit "Не удалось включить network_load.service"
    log_info "Сервис network_load.service запущен"
    # Установка Python-библиотек для мониторинга (psutil через pip)
    pip3 install psutil || error_exit "Не удалось установить библиотеку psutil через pip3"
    log_info "Дополнительные утилиты для мониторинга установлены"
}

# Настройка и запуск сервиса Telegram Bot
telegram_bot() {
    echo "Настройка Telegram Bot Service..."
    tee /etc/systemd/system/telegram_bot.service > /dev/null << 'EOF'
[Unit]
Description=Telegram Bot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/bot_source
ExecStart=/var/www/html/bot_source/venv/bin/python /var/www/html/bot_source/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    touch /var/log/telegram_bot.log
    chown www-data:www-data /var/log/telegram_bot.log
    chmod 664 /var/log/telegram_bot.log
    systemctl daemon-reload
    systemctl enable telegram_bot.service
    systemctl start telegram_bot.service
    python3 -m venv /var/www/html/bot_source/venv
    chown -R "$USER":"$USER" /var/www/html/bot_source/venv
    source /var/www/html/bot_source/venv/bin/activate
    pip install --upgrade pip || log_error "Не удалось обновить pip для Telegram Bot"
    pip install python-telegram-bot psutil requests "python-telegram-bot[job-queue]" || error_exit "Не удалось установить библиотеки для Telegram Bot"
    echo "www-data ALL=NOPASSWD: /bin/systemctl is-active telegram_bot.service, /bin/systemctl start telegram_bot.service, /bin/systemctl stop telegram_bot.service, /bin/systemctl enable telegram_bot.service, /bin/systemctl disable telegram_bot.service" > /etc/sudoers.d/telegram_bot
    chmod 440 /etc/sudoers.d/telegram_bot
    chmod +x /var/www/html/bot_source/bot.py
    chown www-data:www-data /var/www/html/data/telegram_bot_config.json
    chmod 664 /var/www/html/data/telegram_bot_config.json
    echo "Telegram Bot Service успешно настроен и запущен."
}

# Настройка сервиса Home Metrics Daemon (сбор истории метрик)
configure_home_metrics_daemon() {
    log_info "Настраиваю Home Metrics Daemon"
    cat <<'EOF' > /etc/systemd/system/home_metrics_daemon.service
[Unit]
Description=Home Metrics Daemon (Collect CPU/RAM/Disk history)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/home_metrics_daemon.py
Restart=always
RestartSec=2
User=www-data
Group=www-data
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=home-metrics-daemon

[Install]
WantedBy=multi-user.target
EOF
    log_info "Unit-файл home_metrics_daemon.service создан"
    systemctl daemon-reload || error_exit "Не удалось перезагрузить systemd (home_metrics_daemon)"
    systemctl start home_metrics_daemon.service || error_exit "Не удалось запустить home_metrics_daemon.service"
    systemctl enable home_metrics_daemon.service || error_exit "Не удалось включить home_metrics_daemon.service"
    log_info "Сервис home_metrics_daemon.service запущен и включен"
    systemctl restart home_metrics_daemon.service || error_exit "Не удалось перезапустить home_metrics_daemon.service"
    log_info "Сервис home_metrics_daemon.service перезапущен"
    if [ ! -f /var/www/html/data/home_metrics_daemon.json ]; then
        touch /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось создать файл home_metrics_daemon.json"
    fi
    chmod 644 /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось установить права 644 на home_metrics_daemon.json"
    chown www-data:www-data /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось сменить владельца home_metrics_daemon.json"
    log_info "Файл home_metrics_daemon.json готов (права установлены)"
}

# Финальные доработки прав и настроек
finalize_setup() {
    log_info "Выполняю финальные доработки системы"
    # Пропускаем выставление 777 на /var/www/html (уже принадлежит www-data)
    mkdir -p /home/files/.trash/.tmb/
    mkdir -p /home/files/.trash/
    mkdir -p /home/files
    chmod +x /var/www/html/scripts/update.sh 2>/dev/null || true
    chmod +x /usr/local/bin/ping_daemon.sh
    chmod +x /var/www/html/api/scan_local_network.py
    chmod +x /var/www/html/api/update_network_load.py
    chown -R www-data:www-data /home/files
    chown -R www-data:www-data /home/files/.trash/
    chown -R www-data:www-data /home/files/.trash/.tmb/
    chown -R www-data:www-data /var/www/html/data
    [ -f /var/log/vpn-web.log ] && chown www-data:www-data /var/log/vpn-web.log
    chmod -R 755 /home/files
    chmod -R 755 /home/files/.trash/
    chmod -R 755 /home/files/.trash/.tmb/
    chmod -R 755 /var/www/html/data
    [ -f /var/log/vpn-web.log ] && chmod 660 /var/log/vpn-web.log
    usermod -a -G adm www-data
    systemctl restart apache2
    log_info "Финальная настройка прав выполнена"
}

# Удаление всех настроек (деинсталляция VPN и веб-интерфейса)
remove_configuration() {
    services=("openvpn@client1.service" "wg-quick@tun0.service" "isc-dhcp-server" "apache2" "shellinabox" "ping_daemon.service" "dnsmasq")
    for svc in "${services[@]}"; do
        systemctl stop "$svc" 2>/dev/null
        systemctl disable "$svc" 2>/dev/null
    done
    if dpkg -l | grep -qw dnsmasq; then
        log_info "Удаляется dnsmasq"
        apt-get purge -y dnsmasq || log_error "Не удалось удалить dnsmasq"
        log_info "dnsmasq удалён"
    fi
    rm -rf /etc/openvpn /etc/wireguard /var/www/html
    rm -f /etc/dhcp/dhcpd.conf /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases
    rm -f /etc/systemd/system/vpn-update.service /etc/systemd/system/vpn-update.timer || log_error "Не удалось удалить файлы vpn-update.service/timer"
    log_info "Удалены файлы конфигурации VPN"
    apt-get purge -y htop net-tools mtr wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server libapache2-mod-authnz-pam shellinabox dos2unix || log_error "Ошибка удаления пакетов VPN-сервера"
    apt-get autoremove -y
    log_info "Удалены установленные пакеты"
    iptables -t nat -D POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4
    log_info "Удалены правила iptables"
    systemctl daemon-reload
    if [ -f /etc/sudoers.d/vpn_admin ]; then
        echo "Удаляем файл sudoers /etc/sudoers.d/vpn_admin..."
        rm -f /etc/sudoers.d/vpn_admin
    fi
    if [ -f /etc/sudoers.d/telegram_bot ]; then
        echo "Удаляем файл sudoers /etc/sudoers.d/telegram_bot..."
        rm -f /etc/sudoers.d/telegram_bot
    fi
    crontab -u www-data -r 2>/dev/null
    log_info "Cron-задания www-data удалены"
    log_info "Все настройки (VPN и веб-интерфейса) удалены"
}

# Функция проверки работы ключевых сервисов
check_execution() {
    echo -e "\n${YELLOW}[Проверка выполнения] Проверяю запущенные сервисы...${NC}"
    if systemctl is-active --quiet isc-dhcp-server; then
        log_info "ISC-DHCP-SERVER запущен"
    else
        error_exit "ISC-DHCP-SERVER не запущен"
    fi
    if systemctl is-active --quiet apache2; then
        log_info "Apache2 запущен"
    else
        error_exit "Apache2 не запущен"
    fi
    if systemctl is-active --quiet shellinabox; then
        log_info "Shell In A Box запущен"
    else
        error_exit "Shell In A Box не запущен"
    fi
    if ip link show "$IN_IF" >/dev/null 2>&1; then
        log_info "Интерфейс $IN_IF обнаружен в системе"
    else
        error_exit "Интерфейс $IN_IF не обнаружен"
    fi
    if ip link show "$OUT_IF" >/dev/null 2>&1; then
        log_info "Интерфейс $OUT_IF обнаружен"
    else
        error_exit "Интерфейс $OUT_IF не обнаружен"
    fi
    log_info "Проверка выполнения завершена"
}

# ==============================================
echo -e "${YELLOW}==============================================${NC}"
echo -e "${YELLOW}  Установка VPN-сервера с веб-интерфейсом (v2.5.1)${NC}"
echo -e "${YELLOW}==============================================${NC}"
echo ""
echo "Выберите действие:"
echo "1) Установить и настроить сервер"
echo "2) Удалить все настройки сервера"
echo ""
read -r -p "Ваш выбор [1/2]: " action_choice

if [ "$action_choice" == "2" ]; then
    remove_configuration
    echo -e "${YELLOW}[Завершение скрипта]${NC}"
    exit 0
elif [ "$action_choice" != "1" ]; then
    error_exit "Неверный выбор. Выберите 1 или 2"
fi

install_packages

echo "Какое действие выполнить с настройкой сети (Netplan)?"
echo "1) Полная настройка сети (WAN и LAN) и продолжение установки"
echo "2) Только настроить сеть (Netplan) и завершить (без установки VPN)"
echo "3) Пропустить настройку сети (использовать текущую конфигурацию)"
read -r -p "Ваш выбор [1/2/3]: " netplan_choice

case "$netplan_choice" in
    1)
        select_interfaces
        echo "Выберите тип настройки для интерфейса $IN_IF (WAN):"
        echo "1) DHCP (получать IP автоматически)"
        echo "2) Статический IP (ввести вручную)"
        read -r -p "Ваш выбор [1/2]: " ip_mode
        if [ "$ip_mode" == "1" ]; then
            DHCP_INCOMING=1
        elif [ "$ip_mode" == "2" ]; then
            DHCP_INCOMING=0
            read -r -p "Введите статический IP для $IN_IF (без маски): " STATIC_IP
            read -r -p "Введите префикс (маску) сети (например, 24): " SUBNET_MASK
            read -r -p "Введите шлюз (gateway) для $IN_IF: " GATEWAY
            read -r -p "Введите DNS-сервер 1: " DNS1
            read -r -p "Введите DNS-сервер 2: " DNS2
        else
            error_exit "Неверный выбор варианта настройки IP"
        fi
        log_info "Применяю новую сетевую конфигурацию через netplan"
        # Резервная копия и удаление старых netplan-конфигураций
        [ -d /etc/netplan ] || mkdir -p /etc/netplan
        if ls /etc/netplan/*.yaml /etc/netplan/*.yml > /dev/null 2>&1; then
            mkdir -p /etc/netplan/backup
            cp /etc/netplan/*.yaml /etc/netplan/*.yml /etc/netplan/backup/ 2>/dev/null
            rm -f /etc/netplan/*.yaml /etc/netplan/*.yml
        fi
        # Формирование нового netplan-конфига
        NETPLAN_FILE=/etc/netplan/01-network-config.yaml
        echo "# Конфигурация сгенерирована скриптом" > $NETPLAN_FILE
        echo "network:" >> $NETPLAN_FILE
        echo "  version: 2" >> $NETPLAN_FILE
        echo "  renderer: networkd" >> $NETPLAN_FILE
        echo "  ethernets:" >> $NETPLAN_FILE
        echo "    $IN_IF:" >> $NETPLAN_FILE
        if [ "${DHCP_INCOMING}" == "1" ]; then
            echo "      dhcp4: true" >> $NETPLAN_FILE
        else
            echo "      dhcp4: false" >> $NETPLAN_FILE
            echo "      addresses: [${STATIC_IP}/${SUBNET_MASK}]" >> $NETPLAN_FILE
            echo "      gateway4: $GATEWAY" >> $NETPLAN_FILE
            echo "      nameservers:" >> $NETPLAN_FILE
            echo "        addresses: [$DNS1, $DNS2]" >> $NETPLAN_FILE
        fi
        echo "    $OUT_IF:" >> $NETPLAN_FILE
        echo "      dhcp4: false" >> $NETPLAN_FILE
        echo "      addresses: [$LOCAL_IP/24]" >> $NETPLAN_FILE
        echo "      nameservers:" >> $NETPLAN_FILE
        echo "        addresses: [8.8.8.8, 8.8.4.4]" >> $NETPLAN_FILE
        echo "      optional: true" >> $NETPLAN_FILE
        chmod 600 $NETPLAN_FILE
        # Применение netplan и переключение на systemd-networkd
        systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
        systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"
        systemctl disable NetworkManager.service 2>/dev/null || true
        systemctl stop NetworkManager.service 2>/dev/null || true
        netplan apply || error_exit "Не удалось применить netplan-конфигурацию"
        sleep 15
        if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
            error_exit "После настройки сети отсутствует доступ в интернет"
        fi
        log_info "Новая конфигурация сети успешно применена"
        ;;
    2)
        select_interfaces
        # (Логика аналогична варианту 1, но далее скрипт завершается)
        echo "Выберите тип настройки для интерфейса $IN_IF (WAN):"
        echo "1) DHCP (авто)"
        echo "2) Статический IP"
        read -r -p "Ваш выбор [1/2]: " ip_mode2
        if [ "$ip_mode2" == "1" ]; then
            DHCP_INCOMING=1
        elif [ "$ip_mode2" == "2" ]; then
            DHCP_INCOMING=0
            read -r -p "Введите статический IP для $IN_IF: " STATIC_IP
            read -r -p "Введите префикс сети: " SUBNET_MASK
            read -r -p "Введите шлюз для $IN_IF: " GATEWAY
            read -r -p "Введите DNS1: " DNS1
            read -r -p "Введите DNS2: " DNS2
        else
            error_exit "Неверный выбор варианта настройки IP"
        fi
        # Создание netplan-конфига (аналогично пункту 1)
        NETPLAN_FILE=/etc/netplan/01-network-config.yaml
        echo "# Конфигурация сгенерирована скриптом" > $NETPLAN_FILE
        echo "network:" >> $NETPLAN_FILE
        echo "  version: 2" >> $NETPLAN_FILE
        echo "  renderer: networkd" >> $NETPLAN_FILE
        echo "  ethernets:" >> $NETPLAN_FILE
        echo "    $IN_IF:" >> $NETPLAN_FILE
        if [ "${DHCP_INCOMING}" == "1" ]; then
            echo "      dhcp4: true" >> $NETPLAN_FILE
        else
            echo "      dhcp4: false" >> $NETPLAN_FILE
            echo "      addresses: [${STATIC_IP}/${SUBNET_MASK}]" >> $NETPLAN_FILE
            echo "      gateway4: $GATEWAY" >> $NETPLAN_FILE
            echo "      nameservers:" >> $NETPLAN_FILE
            echo "        addresses: [$DNS1, $DNS2]" >> $NETPLAN_FILE
        fi
        echo "    $OUT_IF:" >> $NETPLAN_FILE
        echo "      dhcp4: false" >> $NETPLAN_FILE
        echo "      addresses: [$LOCAL_IP/24]" >> $NETPLAN_FILE
        echo "      nameservers:" >> $NETPLAN_FILE
        echo "        addresses: [8.8.8.8, 8.8.4.4]" >> $NETPLAN_FILE
        echo "      optional: true" >> $NETPLAN_FILE
        chmod 600 $NETPLAN_FILE
        systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
        systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"
        systemctl disable NetworkManager.service 2>/dev/null || true
        systemctl stop NetworkManager.service 2>/dev/null || true
        netplan apply || error_exit "Не удалось применить netplan-конфигурацию"
        sleep 15
        if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
            error_exit "После настройки сети отсутствует доступ в интернет"
        fi
        echo -e "\n${GREEN}[OK]${NC} Настройка сети завершена. Скрипт остановлен по выбору пользователя."
        exit 0
        ;;
    3)
        netplan_file=$(find /etc/netplan -maxdepth 1 -type f -name "*.yaml" | head -n 1)
        if [ -z "$netplan_file" ]; then
            error_exit "Не найден netplan-файл (.yaml). Настройте сеть вручную."
        fi
        if ! grep -q "renderer: networkd" "$netplan_file"; then
            error_exit "Конфигурация $netplan_file не предназначена для systemd-networkd."
        fi
        IN_IF=$(grep -E "^[[:space:]]+[a-zA-Z0-9_-]+:" "$netplan_file" | head -n 1 | awk '{print $1}' | tr -d ':')
        OUT_IF=$(grep -E "^[[:space:]]+[a-zA-Z0-9_-]+:" "$netplan_file" | sed -n '2p' | awk '{print $1}' | tr -d ':')
        LOCAL_IP=$(grep -A 5 -E "^[[:space:]]+$OUT_IF:" "$netplan_file" | grep "addresses:" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        if [ -z "$IN_IF" ] || [ -z "$OUT_IF" ]; then
            error_exit "Не удалось определить сетевые интерфейсы из $netplan_file"
        fi
        if [ -z "$LOCAL_IP" ]; then
            LOCAL_IP="192.168.1.1"
        fi
        log_info "Сеть пропущена: используем существующие настройки ($IN_IF -> WAN, $OUT_IF -> LAN, LAN IP: $LOCAL_IP)"
        systemctl disable NetworkManager.service 2>/dev/null || true
        systemctl stop NetworkManager.service 2>/dev/null || true
        systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
        systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"
        ;;
    *)
        error_exit "Неверный выбор, пожалуйста выберите 1, 2 или 3."
        ;;
esac

configure_dns
configure_dhcp
configure_iptables
configure_vpn
configure_web_interface
configure_apache
configure_shellinabox
configure_ping_daemon
configure_metrics_services
telegram_bot
configure_home_metrics_daemon
finalize_setup
check_execution

echo -e "\n${GREEN}[OK]${NC} Установка завершена успешно!"
echo "После перезагрузки сервера все настройки сети и сервисов будут применены."
echo "Веб-интерфейс доступен по URL: http://$LOCAL_IP/ (учетные данные совпадают с учетной записью сервера)."
echo "Удачи!"
exit 0
