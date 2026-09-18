#!/bin/bash

set -e


echo "Так Юра Педрулин приступает к работе.. ."
# Удаление предыдущей установки Squid
echo "Удаляем прошлый хобот Squid..."
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


# Теперь заметаем прошлые следы
echo "Теперь заметаем прошлые следы"
sudo rm -f /etc/squid/passwd

# Установка HTTPS прокси-сервера (в примере - Squid)
echo "Юра вносить ясность, жди боец, уже скоро"
sudo apt-get update
sudo apt-get install -y squid apache2-utils

# Создание файла паролей
echo "Создание файла паролей..."
sudo touch /etc/squid/passwd
sudo chmod 644 /etc/squid/passwd

# Генерация случайного имени пользователя и пароля
generate_password() {
  < /dev/urandom tr -dc A-Za-z0-9 | head -c12
}

user="userprxy"
pass=$(generate_password)

# Добавление пользователя в файл паролей
echo "Добавление пользователя в файл паролей..."
sudo htpasswd -b /etc/squid/passwd $user $pass

# Конфигурация Squid
echo "Конфигурация Squid..."
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
sudo cat <<EOL > /etc/squid/squid.conf
http_port 3128
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
EOL
echo "Юра Педрулин уже заканчивает с этим"
# Перезапуск службы Squid
echo "Запуск службы Squid..."
sudo systemctl restart squid

# Получение IP-адреса сервера
server_ip=$(hostname -I | awk '{print $1}')

# Вывод данных для подключения
echo " "
echo "    Залупа, у тебя Получилось!"
echo "    HTTPS прокси-сервер Готов Ебать!"
echo "    Быстре Сука копируй уже"
echo "    И Пиздуй Нахуй От Сюда"
echo "==================================================="
echo " "
echo "           IP: $server_ip"
echo "           Порт: 3128"
echo " "
echo "           Пользователь: $user"
echo "           Пароль: $pass"
echo " "
echo "==================================================="
echo " "
