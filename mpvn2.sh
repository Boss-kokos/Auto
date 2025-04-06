#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

echo ""
echo "Добро пожаловать в Настройщик Сервера с Нуля!"
echo ""

# Проверка запуска от root
if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: Скрипт должен быть запущен от пользователя root."
    exit 1
fi

# Вывод списка сетевых интерфейсов с их IP-адресами
echo "Сетевые интерфейсы и их адреса:"
ip -o addr show | awk '/inet / {print $2, $4}' | nl
echo ""

# Запрашиваем у пользователя номера интерфейсов
read -rp "Введите номер внешнего (интернет) интерфейса: " ext_if_num
read -rp "Введите номер внутреннего (локальной сети) интерфейса: " int_if_num

# Получаем имена интерфейсов
mapfile -t interfaces < <(ip -o link show | awk -F': ' '{print $2}')
ext_if=$(echo "${interfaces[$((ext_if_num-1))]}")
int_if=$(echo "${interfaces[$((int_if_num-1))]}")

echo ""
echo "Выбран внешний интерфейс: $ext_if"
echo "Выбран внутренний интерфейс: $int_if"
echo ""

# Выбор типа конфигурации для внешнего интерфейса
echo "Выберите вариант настройки внешнего интерфейса:"
echo "1) Получить адрес от DHCP"
echo "2) Прописать статический адрес"
read -rp "Ваш выбор [1/2]: " net_choice
echo ""

# Резервное копирование существующих конфигураций netplan (если есть)
netplan_conf_dir="/etc/netplan"
if compgen -G "$netplan_conf_dir"/*.yaml > /dev/null; then
    backup_dir="${netplan_conf_dir}/backup_$(date +%s)"
    echo "Создаем резервную копию конфигураций netplan в $backup_dir..."
    mkdir -p "$backup_dir"
    cp "$netplan_conf_dir"/*.yaml "$backup_dir"/
fi

# Удаляем старые конфигурации netplan
rm -f /etc/netplan/*.yaml

# Формирование нового файла конфигурации netplan
netplan_file="/etc/netplan/01-server-setup.yaml"
if [ "$net_choice" == "1" ]; then
    # Внешний интерфейс – DHCP, внутренний – статичный с дефолтными параметрами
    cat <<EOF > "$netplan_file"
network:
  version: 2
  renderer: networkd
  ethernets:
    $ext_if:
      dhcp4: true
    $int_if:
      dhcp4: false
      addresses: [10.10.1.1/20]
      nameservers:
        addresses: [10.10.1.1]
      optional: true
EOF
elif [ "$net_choice" == "2" ]; then
    # Внешний интерфейс – статичный (параметры вводятся пользователем), внутренний – как выше
    read -rp "Введите IP-адрес для внешнего интерфейса (например, 192.168.0.10): " ext_ip
    read -rp "Введите префикс сети (например, 24): " ext_prefix
    read -rp "Введите шлюз для внешнего интерфейса: " ext_gw
    read -rp "Введите DNS-сервер 1: " ext_dns1
    read -rp "Введите DNS-сервер 2: " ext_dns2
    cat <<EOF > "$netplan_file"
network:
  version: 2
  renderer: networkd
  ethernets:
    $ext_if:
      dhcp4: false
      addresses: [$ext_ip/$ext_prefix]
      gateway4: $ext_gw
      nameservers:
        addresses: [$ext_dns1, $ext_dns2]
    $int_if:
      dhcp4: false
      addresses: [10.10.1.1/20]
      nameservers:
        addresses: [10.10.1.1]
      optional: true
EOF
else
    echo "Неверный выбор. Скрипт завершает работу."
    exit 1
fi

chmod 600 "$netplan_file"

echo "Применяем настройки сети..."
if ! netplan apply; then
    echo "Ошибка применения настроек сети."
    exit 1
fi

# Проверка доступа в интернет с циклическим ожиданием (до 30 сек)
echo "Проверка доступа в интернет..."
max_wait=30
waited=0
while ! ping -c1 -W2 google.com &>/dev/null; do
    sleep 2
    waited=$((waited+2))
    if [ $waited -ge $max_wait ]; then
        echo "Ошибка: Интернет-соединение недоступно."
        exit 1
    fi
done
echo "Интернет-соединение доступно."
echo ""

# Обновление системы и установка необходимых пакетов
echo "Обновление системы и установка компонентов..."
apt-get update && apt-get upgrade -y
apt-get install -y htop net-tools mtr network-manager dnsmasq wireguard openvpn apache2 php php-yaml libapache2-mod-php git iptables-persistent openssh-server resolvconf

# Настройка DNS: резервное копирование и добавление записей (если отсутствуют)
RESOLV_CONF="/etc/resolvconf/resolv.conf.d/base"
RESOLV_CONF2="/etc/resolv.conf"
for file in "$RESOLV_CONF" "$RESOLV_CONF2"; do
    if [ -f "$file" ]; then
        cp "$file" "$file.bak_$(date +%s)"
        grep -qxF "nameserver 1.1.1.1" "$file" || echo "nameserver 1.1.1.1" >> "$file"
        grep -qxF "nameserver 8.8.8.8" "$file" || echo "nameserver 8.8.8.8" >> "$file"
    fi
done
resolvconf -u || echo "Не удалось обновить resolvconf."

# Настройка SSH: разрешение входа от root (НЕ РЕКОМЕНДУЕТСЯ для продакшена)
echo "Настройка SSH (разрешаем root login – небезопасно для продакшена)..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart sshd

# Настройка dnsmasq для DHCP и кеширования DNS
echo "Настройка dnsmasq..."
dnsmasq_conf="/etc/dnsmasq.conf"
[ -f "$dnsmasq_conf" ] && cp "$dnsmasq_conf" "$dnsmasq_conf.bak_$(date +%s)"
cat <<EOF >> "$dnsmasq_conf"
dhcp-authoritative
domain=link.lan
listen-address=127.0.0.1,10.10.1.1
dhcp-range=10.10.1.2,10.10.15.254,255.255.240.0,12h
server=8.8.8.8
server=8.8.4.4
cache-size=10000
EOF

systemctl stop systemd-resolved
systemctl disable systemd-resolved
systemctl restart dnsmasq
systemctl enable dnsmasq

# Настройка IP forwarding и NAT через iptables
echo "Настройка NAT..."
sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
sysctl -p
iptables -t nat -A POSTROUTING -o tun0 -s 10.10.1.0/20 -j MASQUERADE
iptables-save > /etc/iptables/rules.v4

# Настройка OpenVPN: включение автоматического старта
echo "Настройка OpenVPN..."
sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn

# Установка корректных прав на конфигурационные директории и файлы
echo "Установка корректных прав..."
chmod 755 /etc/openvpn/
chmod 755 /etc/wireguard/
chmod 600 "$netplan_file"

# Настройка sudoers для www-data (НЕ РЕКОМЕНДУЕТСЯ для продакшена)
cat <<EOF >> /etc/sudoers
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop openvpn*, /bin/systemctl start openvpn*
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop wg-quick*, /bin/systemctl start wg-quick*
www-data ALL=(ALL) NOPASSWD: /bin/systemctl enable wg-quick*, /bin/systemctl disable wg-quick*
www-data ALL=(root) NOPASSWD: /usr/bin/id
www-data ALL=(ALL) NOPASSWD: /usr/sbin/netplan try, /usr/sbin/netplan apply
EOF

# Разрешение входящего HTTP-трафика через iptables
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Развёртывание веб-интерфейса
echo "Настройка веб-интерфейса..."
if [ -d /var/www/html ]; then
    mv /var/www/html "/var/www/html.backup_$(date +%s)"
fi
git clone https://github.com/MineVPN/WebVPNCabinet.git /var/www/html

# Добавление задачи cron для обновления (без перезаписи существующих задач)
(crontab -l 2>/dev/null; echo "0 4 * * * /bin/bash /var/www/html/update.sh") | crontab -

echo ""
echo "Установка завершена!"
echo "Веб-интерфейс доступен по адресу: http://10.10.1.1/ (локальная сеть)"
echo "Пароль от веб-интерфейса совпадает с паролем root (НЕБЕЗОПАСНО для продакшена)"
echo ""
