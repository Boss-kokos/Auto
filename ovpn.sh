#!/usr/bin/env bash
set -euo pipefail

# ====== параметры по умолчанию (переопределяй через переменные окружения) ======
PORT="${PORT:-$(shuf -i 20000-60000 -n1)}"         # пример: 1194 или 443
PROTO="${PROTO:-udp}"                               # udp|tcp
DNS="${DNS:-system}"                                # system|cloudflare|google|opendns|quad9
MODE="${MODE:-single}"                              # single|multi  (multi => duplicate-cn)
CLIENT="${CLIENT:-client1}"                         # имя первого клиента
IPV4_AUTO="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
PUBLIC_IP="${PUBLIC_IP:-$IPV4_AUTO}"

# ====== проверки ======
[[ $EUID -eq 0 ]] || { echo "Запусти как root"; exit 1; }
command -v apt >/dev/null || { echo "Нужен Debian/Ubuntu с apt"; exit 1; }

echo "== Установка OpenVPN (авто) =="
echo "PORT=$PORT PROTO=$PROTO DNS=$DNS MODE=$MODE CLIENT=$CLIENT PUBLIC_IP=$PUBLIC_IP"

# ====== пакеты ======
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y openvpn easy-rsa iptables-persistent netfilter-persistent

# ====== PKI / Easy-RSA ======
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

# ====== tls-crypt ======
openvpn --genkey secret /etc/openvpn/server/tc.key

# ====== DNS push ======
DNS_LINES=""
case "$DNS" in
  system)
    RESOLVCONF='/etc/resolv.conf'
    [[ -f /run/systemd/resolve/resolv.conf ]] && RESOLVCONF='/run/systemd/resolve/resolv.conf'
    while read -r ns; do DNS_LINES+="push \"dhcp-option DNS $ns\"\n"; done < <(grep -v '#' "$RESOLVCONF" | awk '/nameserver/{print $2}')
    ;;
  cloudflare) DNS_LINES=$'push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"\n' ;;
  google)     DNS_LINES=$'push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"\n' ;;
  opendns)    DNS_LINES=$'push "dhcp-option DNS 208.67.222.222"\npush "dhcp-option DNS 208.67.220.220"\n' ;;
  quad9)      DNS_LINES=$'push "dhcp-option DNS 9.9.9.9"\npush "dhcp-option DNS 149.112.112.112"\n' ;;
  *)          DNS_LINES="" ;;
esac

# ====== server.conf ======
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

# Включить общий сертификат если нужно
if [[ "$MODE" == "multi" ]]; then
  echo "duplicate-cn" >> /etc/openvpn/server/server.conf
fi

# ====== форвардинг и NAT ======
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

# ====== шаблон клиента ======
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

# ====== генерация .ovpn в /root ======
gen_client () {
  local NAME="$1"
  local OUT="/root/${NAME}.ovpn"
  cp /etc/openvpn/server/client-common.txt "\$OUT"
  {
    echo "<ca>";        cat /etc/openvpn/server/ca.crt; echo "</ca>"
    echo "<cert>";      sed -ne '/BEGIN CERTIFICATE/,\$p' "/etc/openvpn/easy-rsa/pki/issued/\${NAME}.crt"; echo "</cert>"
    echo "<key>";       cat "/etc/openvpn/easy-rsa/pki/private/\${NAME}.key"; echo "</key>"
    echo "<tls-crypt>"; sed -ne '/BEGIN OpenVPN Static key/,\$p' /etc/openvpn/server/tc.key; echo "</tls-crypt>"
  } >>"\$OUT"
  echo "Создан \$OUT"
}
gen_client "$CLIENT"

systemctl enable --now openvpn-server@server.service

echo "Готово. Импортируй /root/${CLIENT}.ovpn в клиент OpenVPN."
echo "Новый клиент:  cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa build-client-full NAME nopass && bash -c 'gen_client NAME'"
