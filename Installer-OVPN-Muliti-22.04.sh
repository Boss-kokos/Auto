#!/bin/bash
#
# https://github.com/gayankuruppu/openvpn-install-for-multiple-users
# This script enables duplicate-cn in server.conf. You can share the same client.ovpn file for multiple users.
# Based on Nyr https://github.com/Nyr/openvpn-install
#
# Обновлено под Ubuntu 22.04

# Проверка на слишком старую Ubuntu
if grep -qs "Ubuntu 16.04" "/etc/os-release"; then
	echo 'Ubuntu 16.04 больше не поддерживается'
	exit
fi
if grep -qs "Ubuntu 18.04" "/etc/os-release"; then
	echo 'Ubuntu 18.04 больше не поддерживается, обновитесь до 22.04'
	exit
fi
# проверка запуска в bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "Этот скрипт нужно запускать через bash, а не sh"
	exit
fi
# проверка запуска от root
if [[ "$EUID" -ne 0 ]]; then
	echo "Запустите скрипт от root (sudo)"
	exit
fi
# проверка что устройство tun включено
if [[ ! -e /dev/net/tun ]]; then
	echo "Устройство TUN не включено"
	exit
fi

# проверка операционной системы
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
else
	echo "Этот скрипт работает только на Debian, Ubuntu или CentOS"
	exit
fi

newclient () {
	# Создаёт готовый client.ovpn
	cp /etc/openvpn/server/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/server/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

if [[ -e /etc/openvpn/server/server.conf ]]; then
		echo "OpenVPN уже установлен"
		echo
		echo "Всё ещё не можете подключить несколько пользователей?"
		echo "Перезапустите сервер!"
		exit
else
	clear
	echo 'Установка OpenVPN для нескольких пользователей (Ubuntu 22.04)'
	echo
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

	# Настройка OpenVPN и создание первого пользователя
	echo "Определение IPv4 адреса."
	# Автоопределение IP адреса
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	read -p "IP адрес: " -e -i $IP IP
	# Если $IP приватный, сервер за NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Введите публичный IPv4 адрес"
		read -p "Публичный IP: " -e PUBLICIP
	fi
	echo
	echo "Выберите протокол OpenVPN (по умолчанию UDP):"
	echo "   1) UDP (рекомендуется)"
	echo "   2) TCP"
	read -p "Протокол [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1)
		PROTOCOL=udp
		;;
		2)
		PROTOCOL=tcp
		;;
	esac
	echo
	echo "Введите порт OpenVPN (по умолчанию 1194)"
	read -p "Порт: " -e -i 5469 PORT
	echo
	echo "Выберите DNS для VPN (по умолчанию системный)"
	echo "   1) Текущие системные resolvers"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) Verisign"
	read -p "DNS [1-5]: " -e -i 1 DNS
	echo
	echo "Введите имя клиентского сертификата (одно слово)"
	read -p "Имя клиента: " -e -i client CLIENT
	echo
	echo "Пожалуйста, подождите несколько минут"
	read -n1 -r -p "Нажмите любую клавишу для продолжения..."
	# Если внутри контейнера — отключаем LimitNPROC
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo '[Service]
LimitNPROC=infinity' > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates wget curl tar -y
	else
		yum install epel-release -y
		yum install openvpn iptables openssl ca-certificates wget curl tar -y
	fi
	# Получаем easy-rsa (обновлённая версия 3.1.7)
	EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.7/EasyRSA-3.1.7.tgz'
	wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
	tar xzf ~/easyrsa.tgz -C ~/
	mv ~/EasyRSA-3.1.7/ /etc/openvpn/server/
	mv /etc/openvpn/server/EasyRSA-3.1.7/ /etc/openvpn/server/easy-rsa/
	chown -R root:root /etc/openvpn/server/easy-rsa/
	rm -f ~/easyrsa.tgz
	cd /etc/openvpn/server/easy-rsa/
	# Создаём PKI, CA, сертификаты сервера и клиента
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Перемещаем нужные файлы
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL читается при каждом подключении
	chown nobody:$GROUPNAME /etc/openvpn/server/crl.pem
	# Генерируем ключ для tls-auth
	openvpn --genkey secret /etc/openvpn/server/ta.key
	# Файл DH параметров (ffdhe2048)
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Генерируем server.conf
	echo "port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
duplicate-cn
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	# DNS
	case $DNS in
		1)
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
		done
		;;
		2)
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		4)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	# Включаем net.ipv4.ip_forward
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		firewall-cmd --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
ExecStart=/sbin/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=/sbin/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
ExecStop=/sbin/iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=/sbin/iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# SELinux (если включён и нестандартный порт)
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
		if ! hash semanage 2>/dev/null; then
			if grep -qs "CentOS Linux release 7" "/etc/centos-release"; then
				yum install policycoreutils-python -y
			else
				yum install policycoreutils-python-utils -y
			fi
		fi
		semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
	fi
	# Включаем и запускаем OpenVPN
	systemctl enable --now openvpn-server@server.service
	# Если за NAT — используем правильный IP
	if [[ "$PUBLICIP" != "" ]]; then
		IP=$PUBLICIP
	fi
	# client-common.txt — шаблон для будущих пользователей
	echo "client
dev tun
proto $PROTOCOL
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/server/client-common.txt
	# Создаём client.ovpn
	newclient "$CLIENT"
	echo
	echo "Готово!"
	echo
	echo "duplicate-cn добавлен в server.conf"
	echo
	echo "Теперь можно раздать клиентский сертификат неограниченному числу пользователей"
	echo "Перезапустите сервер"
	echo
	echo "Конфигурация клиента доступна тут:" ~/"$CLIENT.ovpn"
fi
