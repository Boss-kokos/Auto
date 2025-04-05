#!/bin/bash

set -e

# Удаление предыдущей установки Squid
echo "Удаление предыдущей установки Squid..."
sudo systemctl stop squid || true
sudo apt-get remove --purge -y squid
sudo apt-get autoremove -y
systemctl disable --now systemd-journald.service
systemctl disable --now syslog.socket rsyslog.service
log_files=("/var/log/auth.log" "/var/log/syslog")

for log_file in "${log_files[@]}"
do
    if [ -f "$log_file" ]; then
        echo "Файл $log_file существует. Удаление..."
        rm "$log_file"
        echo "Файл $log_file успешно удален."
    else
        echo "Файл $log_file не существует."
    fi
done

# Удаление предыдущего файла паролей (если есть)
echo "Удаление предыдущего файла паролей..."
sudo rm -f /etc/squid/passwd

# Установка HTTPS прокси-сервера (Squid)
echo "Установка HTTP прокси-сервера..."
sudo apt-get update
sudo apt-get install -y squid

# Конфигурация Squid для работы с несколькими IP-адресами
echo "Конфигурация Squid для нескольких IP-адресов..."

# Шаблонные IP-адреса, которые вы будете заменять вручную
IP_ADDRESSES=("IP1" "IP2" "IP3" "IP4" "IP5" "IP6")

# Порты для каждого IP-адреса
PORTS=(3128 3129 3130 3131 3132 3133)

sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak

sudo cat <<EOL > /etc/squid/squid.conf
# Основные настройки Squid
acl allowed_ips src ${IP_ADDRESSES[@]}
http_access allow allowed_ips
http_access deny all

# Настройка портов для каждого IP
EOL

for i in "${!IP_ADDRESSES[@]}"; do
    echo "http_port ${IP_ADDRESSES[$i]}:${PORTS[$i]}" | sudo tee -a /etc/squid/squid.conf
done

# Перезапуск службы Squid
echo "Запуск службы Squid..."
sudo systemctl restart squid

# Получение IP-адресов сервера
echo " "
echo " "
echo "    HTTPS прокси-сервер был успешно настроен!"
echo " "
echo "==================================================="
for i in "${!IP_ADDRESSES[@]}"; do
    echo "           IP: ${IP_ADDRESSES[$i]} Порт: ${PORTS[$i]}"
done
echo "==================================================="
echo " "
