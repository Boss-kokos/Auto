#!/usr/bin/env bash
set -euo pipefail

# Поддержка: Debian/Ubuntu. Запуск только от root.
if [[ $EUID -ne 0 ]]; then echo "Запусти как root"; exit 1; fi
if ! command -v apt >/dev/null; then echo "Нужны Debian/Ubuntu с apt"; exit 1; fi

# Параметры по умолчанию
PORT_DEFAULT=1194
PROTO_DEFAULT="udp"
DNS_CHOICE_DEFAULT=1 # 1=System, 2=1.1.1.1, 3=Google

# Ввод
read -r -p "Имя первого клиента (одно слово) [client]: " CLIENT || true
CLIENT=${CLIENT:-client}
read -r -p "Порт [${PORT_DEFAULT}]: " PORT || true
PORT=${PORT:-$PORT_DEFAULT}
read -r -p "Протокол udp/tcp [${PROTO_DEFAULT}]: " PROTO || true
PROTO=${PROTO:-$PROTO_DEFAULT}
read -r -p "DNS 1=System 2=1.1.1.1 3=Google [${DNS_CHOICE_DEFAULT}]: " DNS_CHOICE || true
DNS_CHOICE=${DNS_CHOICE:-$DNS_CHOICE_DEFAULT}

# IP
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
read -r -p "Публичный IPv4 для клиентов [${IPV4}]: " PUBLIC_IP || true
PUBLIC_IP=${PUBLIC_IP:-$IPV4}

# Установка
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa iptables-persistent

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

# tls-crypt
openvpn --genkey --secret /etc/openvpn/server/tc.key

# DNS push
DNS_LINES=""
case "$DNS_CHOICE" in
  1)
    RESOLVCONF='/etc/resolv.conf'
    [[ -f /run/systemd/resolve/resolv.conf ]] && RESOLVCONF='/run/systemd/resolve/resolv.conf'
    for ns in $(grep -v '#' "$RESOLVCONF" | awk '/nameserver/{print $2}'); do
      DNS_LINES+="push \"dhcp-option DNS $ns\"\n"
    done
    ;;
  2) DNS_LINES='push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"\n' ;;
  3) DNS_LINES='push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"\n' ;;
esac

# Конфиг сервера: без duplicate-cn, GCM, tls-crypt
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

# Современная криптография
tls-version-min 1.2
tls-crypt tc.key
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-GCM

# Маршрутизация и DNS
push "redirect-gateway def1 bypass-dhcp"
${DNS_LINES}

keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
verb 3
status /var/log/openvpn-status.log
EOF

# Форвардинг
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/30-openvpn-forward.conf

# NAT через MASQUERADE
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

# Упаковка клиента inline
gen_client () {
  local NAME="\$1"
  local OUT="\$HOME/\${NAME}.ovpn"
  cp /etc/openvpn/server/client-common.txt "\$OUT"
  {
    echo "<ca>"
    cat /etc/openvpn/server/ca.crt
    echo "</ca>"
    echo "<cert>"
    sed -ne '/BEGIN CERTIFICATE/,\$p' "/etc/openvpn/easy-rsa/pki/issued/\${NAME}.crt"
    echo "</cert>"
    echo "<key>"
    cat "/etc/openvpn/easy-rsa/pki/private/\${NAME}.key"
    echo "</key>"
    echo "<tls-crypt>"
    sed -ne '/BEGIN OpenVPN Static key/,\$p' /etc/openvpn/server/tc.key
    echo "</tls-crypt>"
  } >>"\$OUT"
  echo "Готово: \$OUT"
}

gen_client "$CLIENT"

systemctl enable --now openvpn-server@server.service
echo "Установка завершена. Файл клиента: ~/${CLIENT}.ovpn"
echo "Новые пользователи: sudo -H bash -c 'cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa build-client-full NEW nopass && declare -f gen_client >/tmp/gc.sh && source /tmp/gc.sh && gen_client NEW'"
echo "Отзыв сертификата: cd /etc/openvpn/easy-rsa && ./easyrsa revoke USER && ./easyrsa gen-crl && cp pki/crl.pem /etc/openvpn/server/ && systemctl restart openvpn-server@server"
