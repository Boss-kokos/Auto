#!/usr/bin/env bash
set -euo pipefail

# Проверки
[[ $EUID -eq 0 ]] || { echo "Запусти как root"; exit 1; }
command -v apt >/dev/null || { echo "Нужен Debian/Ubuntu с apt"; exit 1; }

# Параметры
RAND_PORT="$(shuf -i 20000-60000 -n1)"
PORT_DEFAULT="${RAND_PORT}"
PROTO_DEFAULT="udp"
DNS_DEFAULT=1  # 1=System, 2=Cloudflare, 3=Google, 4=OpenDNS, 5=Quad9
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"

echo "=== OpenVPN установщик (безопасный) ==="
echo "Внимание: режим 'мульти' включает duplicate-cn (общий сертификат). Это небезопасно."
echo

# Ввод
read -r -p "Порт [${PORT_DEFAULT}]: " PORT || true
PORT=${PORT:-$PORT_DEFAULT}

read -r -p "Протокол 1=udp 2=tcp [1]: " PROTO_CH || true
case "${PROTO_CH:-1}" in 1) PROTO="udp";; 2) PROTO="tcp";; *) PROTO="$PROTO_DEFAULT";; esac

echo "DNS: 1=System 2=1.1.1.1 3=8.8.8.8 4=OpenDNS 5=Quad9"
read -r -p "Выбор DNS [${DNS_DEFAULT}]: " DNS_CH || true
DNS_CH=${DNS_CH:-$DNS_DEFAULT}

read -r -p "Публичный IPv4 для клиентов [${IPV4}]: " PUBLIC_IP || true
PUBLIC_IP=${PUBLIC_IP:-$IPV4}

echo "Режим клиентов: 1=каждому свой конфиг, 2=мульти (общий конфиг)"
read -r -p "Выбор [1/2]: " MODE || true
MODE=${MODE:-1}

# Имя(ена) клиента
if [[ "$MODE" == "2" ]]; then
  read -r -p "Имя общего клиента [shared]: " CLIENT || true
  CLIENT=${CLIENT:-shared}
else
  read -r -p "Имя первого клиента [client1]: " CLIENT || true
  CLIENT=${CLIENT:-client1}
fi

# Установка пакетов
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y openvpn easy-rsa iptables-persistent netfilter-persistent

# Easy-RSA
install -d -m 700 /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa

./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$CLIENT" nopass
EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

install -d -m 755 /etc/openvpn/server
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server/
chown nobody:nogroup /etc/openvpn/server/crl.pem

# tls-crypt ключ
openvpn --genkey secret /etc/openvpn/server/tc.key

# DNS строки
DNS_LINES=""
case "$DNS_CH" in
  1)
    RESOLVCONF='/etc/resolv.conf'
    [[ -f /run/systemd/resolve/resolv.conf ]] && RESOLVCONF='/run/systemd/resolve/resolv.conf'
    for ns in $(grep -v '#' "$RESOLVCONF" | awk '/nameserver/{print $2}'); do
      DNS_LINES+="push \"dhcp-option DNS $ns\"\n"
    done
    ;;
  2) DNS_LINES='push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"\n' ;;
  3) DNS_LINES='push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"\n' ;;
  4) DNS_LINES='push "dhcp-option DNS 208.67.222.222"\npush "dhcp-option DNS 208.67.220.220"\n' ;;
  5) DNS_LINES='push "dhcp-option DNS 9.9.9.9"\npush "dhcp-option DNS 149.112.112.112"\n' ;;
esac

# Конфиг сервера
cat >/etc/openvpn/server/server.conf <<EOF
port ${PORT}
proto ${PROTO}
dev tun
topology subnet
server 10.8.0.0 255.255.255.0

ca ca.crt
cert server.crt
key server.key
crl-verify crl.pem

tls-version-min 1.2
tls-crypt tc.key
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-GCM

push "redirect-gateway def1 bypass-dhcp"
${DNS_LINES}keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
verb 3
status /var/log/openvpn-status.log
EOF

# duplicate-cn для мульти при необходимости
if [[ "$MODE" == "2" ]]; then
  echo "duplicate-cn" >> /etc/openvpn/server/server.conf
fi

# Форвардинг и NAT
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/30-openvpn-forward.conf

IFACE="$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
iptables -C INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT
iptables -C FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save

# Клиентский шаблон
cat >/etc/openvpn/server/client-common.txt <<EOF
client
dev tun
proto ${PROTO}
remote ${PUBLIC_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
key-direction 1
verb 3
EOF

# Генерация .ovpn в /root
gen_client () {
  local NAME="\$1"
  local OUT="/root/\${NAME}.ovpn"
  cp /etc/openvpn/server/client-common.txt "\$OUT"
  {
    echo "<ca>";        cat /etc/openvpn/server/ca.crt; echo "</ca>"
    echo "<cert>";      sed -ne '/BEGIN CERTIFICATE/,\$p' "/etc/openvpn/easy-rsa/pki/issued/\${NAME}.crt"; echo "</cert>"
    echo "<key>";       cat "/etc/openvpn/easy-rsa/pki/private/\${NAME}.key"; echo "</key>"
    echo "<tls-crypt>"; sed -ne '/BEGIN OpenVPN Static key/,\$p' /etc/openvpn/server/tc.key; echo "</tls-crypt>"
  } >>"\$OUT"
  echo "Создан /root/\${NAME}.ovpn"
}

# Первый клиент
gen_client "$CLIENT"

systemctl enable --now openvpn-server@server.service

# Режим “по одному клиенту” — цикл добавления
if [[ "$MODE" != "2" ]]; then
  while true; do
    read -r -p "Добавить ещё клиента? [y/N]: " yn || true
    [[ "${yn:-N}" =~ ^[Yy]$ ]] || break
    read -r -p "Имя клиента: " NEWC
    [[ -n "${NEWC:-}" ]] || continue
    EASYRSA_BATCH=1 ./easyrsa build-client-full "$NEWC" nopass
    gen_client "$NEWC"
  done
fi

echo "Готово. Файлы клиентов в /root/*.ovpn"
[[ "$MODE" == "2" ]] && echo "ВНИМАНИЕ: включён duplicate-cn (общий файл). Лучше выдавать отдельные сертификаты."
