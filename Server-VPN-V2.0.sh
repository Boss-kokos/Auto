#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# Скрипт автонастройки VPN-раздачи интернета в локальную сеть + Веб-интерфейс
# ----------------------------------------------------------------------------
# Версия: 5.1.0
# ----------------------------------------------------------------------------
# Основные изменения:
#  - Отключаем systemd-resolved на Mint, чтобы dnsmasq занял порт 53.
#  - Убираем чрезмерную анимацию: оставляем спиннер только на установке больших пакетов.
#  - debconf-set-selections для iptables-persistent (убираем диалог).
# ----------------------------------------------------------------------------

# ============================== ЦВЕТА ========================================
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BOLD="\e[1m"
NC="\e[0m"   # сброс цвета

SCRIPT_VERSION="5.1.0"

LOG_BASE_DIR="$HOME/log"
LOG_SETUP_DIR="$LOG_BASE_DIR/vpn-setup"
LOG_MONITOR_DIR="$LOG_BASE_DIR/vpn-monitor"
LOG_RETENTION_DAYS=7

NETPLAN_BACKUP_DIR="/etc/netplan/backup_$(date +%Y%m%d_%H%M%S)"
NETPLAN_MAIN_FILE="/etc/netplan/01-my-network-setup.yaml"

VPN_MONITOR_INTERVAL="60"

# ========================== ЛОГИРОВАНИЕ ======================================
get_today_logfile() {
  local log_subdir="$1"
  local logdir="${LOG_BASE_DIR}/${log_subdir}"
  mkdir -p "$logdir"
  find "$logdir" -type f -mtime +$LOG_RETENTION_DAYS -exec rm -f {} \; 2>/dev/null
  local logfile="${logdir}/${log_subdir}-$(date +%Y-%m-%d).log"
  echo "$logfile"
}

log_message() {
  local log_subdir="$1"
  local level="$2"
  local message="$3"

  local logfile
  logfile="$(get_today_logfile "$log_subdir")"

  local timestamp
  timestamp="$(date "+%Y-%m-%d %H:%M:%S")"

  echo "[$timestamp] [$level] $message" | tee -a "$logfile"
}

log_setup_info()    { log_message "vpn-setup" "INFO"  "$1"; }
log_setup_error()   { log_message "vpn-setup" "ERROR" "$1"; }
log_monitor_info()  { log_message "vpn-monitor" "INFO"  "$1"; }
log_monitor_error() { log_message "vpn-monitor" "ERROR" "$1"; }

# ======================== ПОЛЕЗНЫЕ ФУНКЦИИ ===================================
spinner_while() {
  # Запускаем команду в фоне
  local cmd="$*"
  bash -c "$cmd" &
  local pid=$!

  local sp='|/-\'
  local i=0

  while kill -0 "$pid" 2>/dev/null; do
    printf " [%c] " "${sp:i:1}"
    i=$(( (i+1) % ${#sp} ))
    sleep 0.1
    printf "\b\b\b\b"
  done
  wait "$pid"
  return $?
}

print_status() {
  local status_code=$1
  local block_name="$2"
  if [ "$status_code" -eq 0 ]; then
    echo -e "${GREEN}${block_name} - УСПЕШНО${NC}"
  else
    echo -e "${RED}${block_name} - ERROR${NC}"
  fi
}

abort_script() {
  local block_name="$1"
  local reason="$2"
  echo -e "\n${RED}ОШИБКА во время выполнения блока '${block_name}':${NC} $reason"
  log_setup_error "Скрипт остановлен на этапе '${block_name}': $reason"
  echo -e "\nВозврат в главное меню..."
  read -r -p "Нажмите Enter для продолжения..."
}

check_ubuntu_or_mint() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "ubuntu" || "$ID" == "linuxmint" ]]; then
      return 0
    fi
  fi
  echo -e "${RED}Предупреждение: дистрибутив не Ubuntu/Mint! Работа не гарантируется...${NC}"
  return 0
}

# ================== ОТКЛЮЧЕНИЕ systemd-resolved (Mint) ======================
disable_systemd_resolved() {
  echo -e "${YELLOW}Отключаем systemd-resolved, чтобы dnsmasq занял 53 порт...${NC}"
  log_setup_info "Отключение systemd-resolved."
  # Стопим и дизейблим
  sudo systemctl stop systemd-resolved
  sudo systemctl disable systemd-resolved

  # Правим /etc/resolv.conf
  sudo rm -f /etc/resolv.conf
  # Подставляем базовый DNS
  echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf >/dev/null
  # Перезапуск NM на всякий
  sudo systemctl restart NetworkManager
}

# ================== 1. ПОЛНОЕ ОБНОВЛЕНИЕ СИСТЕМЫ ============================
remove_ufw_if_installed() {
  if dpkg -s ufw &>/dev/null; then
    echo "Обнаружен ufw. Удаляем (во избежание конфликтов iptables-persistent)."
    spinner_while "sudo apt-get remove --purge -y ufw"
    spinner_while "sudo apt-get autoremove -y"
    echo "ufw удалён."
  fi
}

full_system_upgrade() {
  echo -e "\n${YELLOW}Начинаем обновление системы (apt-get update && apt-get upgrade)...${NC}"
  log_setup_info "Полное обновление системы..."
  spinner_while "sudo apt-get update && sudo apt-get upgrade -y"
  local result=$?
  print_status $result "Обновление системы"
  [ $result -ne 0 ] && abort_script "Обновление системы" "apt-get upgrade завершился ошибкой" && return 1
  log_setup_info "Система обновлена."
  return 0
}

# ============ 2. УДАЛЕНИЕ (ИЛИ ПЕРЕИМЕНОВАНИЕ) СТАРЫХ VPN-КОНФИГОВ ==========
remove_or_backup_old_configs() {
  echo -e "\nХотите удалить (или переименовать в backup_) старые VPN-конфиги? (y/n)"
  read -r ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    log_setup_info "Удаление/переименование старых VPN-конфигов."
    if [ -d /etc/openvpn ]; then
      for cfg in /etc/openvpn/*.conf /etc/openvpn/*.ovpn; do
        [ -f "$cfg" ] && sudo mv "$cfg" "${cfg}.backup_$(date +%Y%m%d_%H%M%S)"
      done
    fi
    if [ -d /etc/wireguard ]; then
      for cfg in /etc/wireguard/*.conf; do
        [ -f "$cfg" ] && sudo mv "$cfg" "${cfg}.backup_$(date +%Y%m%d_%H%M%S)"
      done
    fi
    echo "Старые VPN-конфиги переименованы."
  else
    echo "Пропускаем удаление старых конфигов."
  fi
}

# ============ 3. ВЫБОР СЕТЕВЫХ ИНТЕРФЕЙСОВ ==================================
select_interfaces() {
  echo ""
  echo "Определяем все интерфейсы (IPv4), кроме lo..."
  log_setup_info "Определение сетевых интерфейсов (IPv4)."

  local interfaces_and_addresses
  interfaces_and_addresses=$(ip -o -4 addr show | awk '{print $2 ": " $4}' | sed 's/\/.*//')

  local all_interfaces
  all_interfaces=$(ip -o link show | awk '$2 != "lo:" {print $2}' | sed 's/://')

  local full_list=""
  for iface in $all_interfaces; do
    if echo "$interfaces_and_addresses" | grep -q "$iface"; then
      local ip_addr
      ip_addr=$(echo "$interfaces_and_addresses" | grep "$iface" | awk '{print $2}')
      full_list+="$iface: $ip_addr\n"
    else
      full_list+="$iface: нет IP-адреса (возможно для LAN)\n"
    fi
  done

  echo "Сетевые адреса/интерфейсы:"
  echo -e "$full_list" | nl
  echo ""

  read -p "Укажи номер (по списку) ВХОДЯЩЕГО (WAN) интерфейса: " num_wan
  read -p "Укажи номер (по списку) ВЫХОДЯЩЕГО (LAN) интерфейса: " num_lan

  local wan_iface
  local lan_iface
  wan_iface=$(echo -e "$full_list" | awk -v num="$num_wan" 'NR == num {print $1}' )
  lan_iface=$(echo -e "$full_list" | awk -v num="$num_lan" 'NR == num {print $1}' )

  wan_iface=${wan_iface%:}
  lan_iface=${lan_iface%:}

  echo "WAN: $wan_iface"
  echo "LAN: $lan_iface"

  SELECTED_WAN_IF="$wan_iface"
  SELECTED_LAN_IF="$lan_iface"
}

# ============ 4. BACKUP/RESTORE NETPLAN ======================================
backup_netplan_configs() {
  [ ! -d "$NETPLAN_BACKUP_DIR" ] && mkdir -p "$NETPLAN_BACKUP_DIR"
  cp -a /etc/netplan/*.yaml "$NETPLAN_BACKUP_DIR" 2>/dev/null || true
  log_setup_info "Бэкап netplan в: $NETPLAN_BACKUP_DIR"
}

restore_netplan_configs() {
  if [ -d "$NETPLAN_BACKUP_DIR" ]; then
    rm -f /etc/netplan/*.yaml
    cp -a "$NETPLAN_BACKUP_DIR"/*.yaml /etc/netplan/ 2>/dev/null || true
    log_setup_info "Восстановлен netplan из: $NETPLAN_BACKUP_DIR"
  else
    log_setup_error "Папка с бэкапом netplan не найдена"
    echo "Откат невозможен: нет бэкапа."
  fi
}

remove_our_netplan_file() {
  [ -f "$NETPLAN_MAIN_FILE" ] && rm -f "$NETPLAN_MAIN_FILE"
}

# ============ 5. ПРОВЕРКА ИНТЕРНЕТА (DNS + HTTP) ============================
check_internet_with_animation() {
  echo ""
  echo "Проверяем доступ к Интернету (DNS + HTTP)..."
  local test_domain="www.google.com"
  local fallback_ip="8.8.8.8"
  local res

  echo -n "Тест curl к $test_domain"
  for i in {1..3}; do echo -n "."; sleep 0.3; done
  echo ""

  res=$(curl -s -o /dev/null -w "%{http_code}" "http://${test_domain}" --max-time 5)
  if [ "$res" == "200" ]; then
    echo "Получен код 200 от $test_domain"
    return 0
  else
    echo "Не получили 200 (код $res). Пробуем ping к $fallback_ip..."
    if ping -c1 -W2 "$fallback_ip" &>/dev/null; then
      echo "ICMP ОК, DNS проблема?"
      return 1
    else
      echo "Интернет недоступен целиком."
      return 2
    fi
  fi
}

# ============ 6. НАСТРОЙКА СЕТИ (NETPLAN + DNSMASQ) =========================
configure_network() {
  local block_name="Настройка сетей (Netplan + dnsmasq)"
  echo -e "\n===== $block_name ====="

  backup_netplan_configs
  remove_our_netplan_file

  echo "Будет LAN: 192.168.1.1 (по умолчанию)."
  read -p "Введите локальный IP (192.168.X.1) или Enter для 192.168.1.1: " local_ip
  [ -z "$local_ip" ] && local_ip="192.168.1.1"

  if [[ ! "$local_ip" =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
    print_status 1 "$block_name"
    abort_script "$block_name" "Неверный IP формат: $local_ip"
    return 1
  fi

  echo "Способ получения WAN IP:"
  echo "1) DHCP"
  echo "2) Статический"
  read -p "Ваш выбор (1/2): " wan_choice

  local wan_config=""
  local lan_config="      dhcp4: false
      addresses: [$local_ip/24]
      nameservers:
        addresses: [1.1.1.1, 1.0.0.1]
      optional: true"

  if [ "$wan_choice" == "1" ]; then
    wan_config="      dhcp4: true"
  elif [ "$wan_choice" == "2" ]; then
    echo "IP (пример: 46.98.249.14)?"
    read -p "WAN IP: " wan_ip
    echo "Маска (пример: 24)?"
    read -p "WAN CIDR: " wan_cidr
    [ -z "$wan_cidr" ] && wan_cidr="24"
    echo "Шлюз (пример: 46.98.249.13)?"
    read -p "WAN Gateway: " wan_gw
    echo "DNS1:"
    read -p "DNS1: " wan_dns1
    echo "DNS2:"
    read -p "DNS2: " wan_dns2

    wan_config="      dhcp4: false
      addresses: [$wan_ip/$wan_cidr]
      gateway4: $wan_gw
      nameservers:
        addresses: [$wan_dns1, $wan_dns2]"
  else
    print_status 1 "$block_name"
    abort_script "$block_name" "Неправильный ввод (WAN Choice)"
    return 1
  fi

  sudo bash -c "cat <<EOF > $NETPLAN_MAIN_FILE
network:
  version: 2
  renderer: networkd
  ethernets:
    $SELECTED_WAN_IF:
$wan_config
    $SELECTED_LAN_IF:
$lan_config
EOF"

  echo "Применяем netplan..."
  spinner_while "sudo netplan apply"
  local nres=$?
  if [ $nres -ne 0 ]; then
    print_status $nres "$block_name"
    abort_script "$block_name" "netplan apply неуспешен!"
    restore_netplan_configs
    spinner_while "sudo netplan apply"
    return 1
  fi

  check_internet_with_animation
  local inet_check=$?
  if [ $inet_check -eq 0 ]; then
    echo "Интернет доступен."
  else
    print_status 1 "$block_name"
    abort_script "$block_name" "Нет интернета (код=$inet_check)."
    remove_our_netplan_file
    restore_netplan_configs
    spinner_while "sudo netplan apply"
    return 1
  fi

  # Установка dnsmasq
  echo "Устанавливаем dnsmasq..."
  spinner_while "sudo apt-get install -y dnsmasq"
  local dns_ok=$?
  if [ $dns_ok -ne 0 ]; then
    print_status $dns_ok "$block_name"
    abort_script "$block_name" "dnsmasq не установился!"
    return 1
  fi

  sudo bash -c "cat <<EOD > /etc/dnsmasq.conf
dhcp-authoritative
domain=office.net
listen-address=127.0.0.1,$local_ip
dhcp-range=${local_ip%.*}.2,${local_ip%.*}.254,255.255.255.0,12h
server=1.1.1.1
server=1.0.0.1
cache-size=10000
EOD"

  sudo systemctl enable dnsmasq
  sudo systemctl restart dnsmasq

  # Включаем ip_forward
  sudo sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
  sudo sysctl -p

  print_status 0 "$block_name"
  return 0
}

# ============ 7. УСТАНОВКА VPN + WEB ========================================
install_vpn_and_web() {
  local block_name="Установка VPN + Web"
  echo -e "\n===== $block_name ====="

  # Удаляем ufw если есть
  remove_ufw_if_installed

  # Автоматический ответ для iptables-persistent
  sudo debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
  export DEBIAN_FRONTEND=noninteractive

  echo "Устанавливаем OpenVPN, WireGuard, Apache2, PHP, Git и т.д."
  spinner_while "sudo apt-get install -y \
       htop net-tools mtr network-manager wireguard openvpn apache2 php git \
       iptables-persistent openssh-server resolvconf speedtest-cli nload \
       libapache2-mod-php wget openvswitch-switch"
  local res=$?
  unset DEBIAN_FRONTEND

  if [ $res -ne 0 ]; then
    print_status $res "$block_name"
    abort_script "$block_name" "Ошибка установки пакетов"
    return 1
  fi

  # OpenVSwitch
  sudo systemctl start openvswitch-switch
  sudo systemctl enable openvswitch-switch

  # SSH - PermitRootLogin yes
  sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
  sudo systemctl restart ssh

  # Iptables (пример: MASQUERADE на tun0)
  sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
  sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null

  # Ставим веб-интерфейс
  echo "Готовим веб-интерфейс..."
  sudo rm -rf /var/www/html
  sudo git clone https://github.com/Rostarc/VPN-Web-Installer.git /var/www/html
  sudo chown -R www-data:www-data /var/www/html
  sudo chmod -R 755 /var/www/html

  # Ограничим доступ .htaccess
  sudo bash -c "cat <<EOD > /var/www/html/.htaccess
<RequireAll>
  Require ip 192.168
</RequireAll>
EOD"

  sudo a2enmod rewrite
  sudo systemctl restart apache2

  # Разрешение sudo для www-data
  sudo bash -c 'cat <<EOD >> /etc/sudoers
www-data ALL=(ALL) NOPASSWD: ALL
EOD'

  print_status 0 "$block_name"
  return 0
}

# =========== 8. МОНИТОРИНГ VPN (SCRIPT + systemd) ===========================
create_vpn_monitor_script() {
  sudo bash -c "cat <<'EOF' > /usr/local/bin/vpn-monitor.sh
#!/usr/bin/env bash

LOG_DIR=\"$HOME/log/vpn-monitor\"
mkdir -p \"\$LOG_DIR\"
find \"\$LOG_DIR\" -type f -mtime +7 -exec rm -f {} \\; 2>/dev/null

LOG_FILE=\"\$LOG_DIR/vpn-monitor-\$(date +%Y-%m-%d).log\"

timestamp() {
  date +\"%Y-%m-%d %H:%M:%S\"
}

write_log() {
  local level=\"\$1\"
  local message=\"\$2\"
  echo \"[\$(timestamp)] [\$level] \$message\" >> \"\$LOG_FILE\"
}

# Проверка OpenVPN
if systemctl is-active --quiet openvpn@client1.service; then
  write_log \"INFO\" \"OpenVPN (client1) активен.\"
else
  write_log \"ERROR\" \"OpenVPN (client1) не активен! Перезапуск...\"
  systemctl restart openvpn@client1.service
  sleep 5
  if systemctl is-active --quiet openvpn@client1.service; then
    write_log \"INFO\" \"OpenVPN (client1) успешно перезапущен.\"
  else
    write_log \"ERROR\" \"OpenVPN (client1) не удалось перезапустить.\"
  fi
fi

# Проверка WireGuard
if systemctl is-active --quiet wg-quick@tun0.service; then
  write_log \"INFO\" \"WireGuard (tun0) активен.\"
else
  write_log \"ERROR\" \"WireGuard (tun0) не активен! Перезапуск...\"
  systemctl restart wg-quick@tun0.service
  sleep 5
  if systemctl is-active --quiet wg-quick@tun0.service; then
    write_log \"INFO\" \"WireGuard (tun0) успешно перезапущен.\"
  else
    write_log \"ERROR\" \"WireGuard (tun0) не удалось перезапустить.\"
  fi
fi

# Пинг google.com
PING_COUNT=5
if ping -c \$PING_COUNT www.google.com >/dev/null 2>&1; then
  write_log \"INFO\" \"www.google.com пингуется.\"
else
  write_log \"ERROR\" \"www.google.com не пингуется!\"
fi

EOF"

  sudo chmod +x /usr/local/bin/vpn-monitor.sh
}

create_vpn_monitor_systemd_units() {
  sudo bash -c "cat <<EOF > /etc/systemd/system/vpn-monitor.service
[Unit]
Description=VPN Monitor Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn-monitor.sh
RemainAfterExit=true
EOF"

  sudo bash -c "cat <<EOF > /etc/systemd/system/vpn-monitor.timer
[Unit]
Description=Run vpn-monitor.service every ${VPN_MONITOR_INTERVAL} seconds

[Timer]
OnUnitActiveSec=${VPN_MONITOR_INTERVAL}
AccuracySec=1s
Unit=vpn-monitor.service

[Install]
WantedBy=multi-user.target
EOF"
}

enable_vpn_monitor() {
  local block_name="VPN-мониторинг (timer)"
  echo -e "\n===== $block_name ====="
  create_vpn_monitor_script
  create_vpn_monitor_systemd_units
  sudo systemctl daemon-reload
  sudo systemctl enable vpn-monitor.timer
  sudo systemctl start vpn-monitor.timer
  local res=$?
  print_status $res "$block_name"
  [ $res -eq 0 ] && echo "Мониторинг VPN запущен." || abort_script "$block_name" "Не удалось запустить таймер"
}

# ========== 9. УДАЛЕНИЕ НАСТРОЕК И ОТКАТ ====================================
remove_all_settings() {
  local block_name="Удаление всех настроек"
  echo -e "\n===== $block_name ====="

  sudo systemctl stop openvpn@client1.service wg-quick@tun0.service \
       dnsmasq.service apache2.service 2>/dev/null || true
  sudo systemctl disable openvpn@client1.service 2>/dev/null || true
  sudo systemctl disable wg-quick@tun0.service 2>/dev/null || true

  sudo rm -rf /etc/openvpn
  sudo rm -rf /etc/wireguard

  spinner_while "sudo apt-get purge -y wireguard openvpn dnsmasq"
  spinner_while "sudo apt-get autoremove -y"

  sudo rm -rf /var/www/html

  sudo iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true
  sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null

  remove_our_netplan_file
  restore_netplan_configs
  spinner_while "sudo netplan apply"

  # Удаляем мониторинг
  sudo systemctl disable vpn-monitor.service 2>/dev/null || true
  sudo systemctl stop vpn-monitor.service 2>/dev/null || true
  sudo rm -f /etc/systemd/system/vpn-monitor.service
  sudo systemctl disable vpn-monitor.timer 2>/dev/null || true
  sudo systemctl stop vpn-monitor.timer 2>/dev/null || true
  sudo rm -f /etc/systemd/system/vpn-monitor.timer
  sudo rm -f /usr/local/bin/vpn-monitor.sh

  print_status 0 "$block_name"
  log_setup_info "Выполнено удаление и откат."
}

# ========= 10. ВОССТАНОВИТЬ NETPLAN =========================================
restore_only_netplan() {
  local block_name="Восстановление netplan"
  echo -e "\n===== $block_name ====="
  remove_our_netplan_file
  restore_netplan_configs
  spinner_while "sudo netplan apply"
  local r=$?
  print_status $r "$block_name"
  [ $r -ne 0 ] && abort_script "$block_name" "netplan apply не удалось."
}

# =========================== ГЛАВНОЕ МЕНЮ ====================================
main_menu() {
  clear
  echo "============================================================="
  echo " Скрипт автонастройки (версия ${SCRIPT_VERSION})"
  echo " VPN + Web + DHCP (dnsmasq) + Monitoring"
  echo "============================================================="
  echo ""
  echo "Выбери опцию:"
  echo "1) Полная настройка (Сеть + VPN + Web + Мониторинг)"
  echo "2) Настроить только сети (DHCP, netplan)"
  echo "3) Установка только VPN + Web (без изменения сети)"
  echo "4) Удалить все настройки (VPN, dnsmasq) и откатить netplan"
  echo "5) Восстановить netplan из бэкапа"
  echo ""

  read -p "Ваш выбор [1/2/3/4/5]: " choice
  case "$choice" in
    1)
      # Полная
      select_interfaces
      configure_network
      [ $? -ne 0 ] && return
      install_vpn_and_web
      [ $? -ne 0 ] && return
      enable_vpn_monitor
      ;;
    2)
      select_interfaces
      configure_network
      ;;
    3)
      install_vpn_and_web
      ;;
    4)
      remove_all_settings
      ;;
    5)
      restore_only_netplan
      ;;
    *)
      echo "Некорректный ввод. Повторите."
      ;;
  esac

  echo ""
  echo "======================================"
  echo -e "${GREEN}Все выбранные действия выполнены (или прерваны ошибкой).${NC}"
  echo "======================================"
}

# ========================== ЗАПУСК СКРИПТА ===================================
check_ubuntu_or_mint

# 1) Отключаем systemd-resolved (даже если это Ubuntu Desktop), чтобы dnsmasq занял порт 53
disable_systemd_resolved

# 2) Полный upgrade
full_system_upgrade
[ $? -ne 0 ] && exit 1

# 3) Предложить удалить старые VPN-конфиги
remove_or_backup_old_configs

# 4) Запуск меню
main_menu
