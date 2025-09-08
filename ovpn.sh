#!/usr/bin/env bash
set -euo pipefail

# ===== общие =====
[[ $EUID -eq 0 ]] || { echo "Нужен root"; exit 1; }
command -v apt >/dev/null || { echo "Нужен Debian/Ubuntu"; exit 1; }
AUTO="${1:-}"  # --defaults = без вопросов

# ===== дефолты =====
RAND_PORT="$(shuf -i 20000-60000 -n1)"
PORT_DEF="$RAND_PORT"
IPV4_DEF="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}')"
[[ -z "${IPV4_DEF:-}" ]] && IPV4_DEF="$(hostname -I | awk '{print $1}')"
DNS_DEF=1  # 1=System, 2=Cloudflare, 3=Google, 4=OpenDNS, 5=Quad9

ask(){ # ask VAR DEFAULT "Prompt"
  local v="$1" d="$2" p="$3"
  if [[ "$AUTO" == "--defaults" ]]; then printf -v "$v" '%s' "$d"; echo "$p [$d]: $d"
  else read -e -i "$d" -p "$p [$d]: " "$v"; [[ -z "${!v}" ]] && printf -v "$v" '%s' "$d"
  fi
}
menu_proto(){
  echo "Протокол:"; echo "  1) UDP"; echo "  2) TCP"
  if [[ "$AUTO" == "--defaults" ]]; then CH="1"; echo "Ваш выбор [1]: 1"
  else read -e -i "1" -p "Ваш выбор [1]: " CH; fi
  case "${CH:-1}" in 1) PROTO="udp";; 2) PROTO="tcp";; *) PROTO="udp";; esac
}
menu_dns(){
  echo "DNS:"; echo "  1) System"; echo "  2) Cloudflare 1.1.1.1"; echo "  3) Google 8.8.8.8"; echo "  4) OpenDNS"; echo "  5) Quad9"
  if [[ "$AUTO" == "--defaults" ]]; then DNS_CH="$DNS_DEF"; echo "Ваш выбор [$DNS_DEF]: $DNS_DEF"
  else read -e -i "$DNS_DEF" -p "Ваш выбор [$DNS_DEF]: " DNS_CH; fi
  DNS_CH=${DNS_CH:-$DNS_DEF}
}
menu_mode(){
  echo "Режим клиентов:"; echo "  1) Каждый свой конфиг (рекомендуется)"; echo "  2) Мульти (duplicate-cn, небезопасно)"
  if [[ "$AUTO" == "--defaults" ]]; then MODE="1"; echo "Ваш выбор [1]: 1"
  else read -e -i "1" -p "Ваш выбор [1]: " MODE; fi
  MODE=${MODE:-1}
}

echo "=== Установка OpenVPN ==="
ask PORT      "$PORT_DEF" "Порт"
menu_proto
menu_dns
ask PUBLIC_IP "$IPV4_DEF" "Публичный IPv4 для клиентов"
menu_mode
if [[ "$MODE" == "2" ]]; then ask CLIENT "shared"  "Имя общего клиента"
else                             ask CLIENT "client1" "Имя первого клиента"; fi

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y openvpn easy-rsa iptables-persistent

# UFW (если активен) — открыть порт
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT/$PROTO" || true
fi

# ===== PKI / Easy-RSA =====
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

# ===== tls-crypt =====
openvpn --genkey secret /etc/openvpn/server/tc.key

# ===== DNS push =====
DNS_LINES=""
case "$DNS_CH" in
  1)
    RESOLVCONF='/etc/resolv.conf'; [[ -f /run/systemd/resolve/resolv.conf ]] && RESOLVCONF='/run/systemd/resolve/resolv.conf'
    while read -r ns; do DNS_LINES+="push \"dhcp-option DNS $ns\"\n"; done < <(grep -v '#' "$RESOLVCONF" | awk '/nameserver/{print $2}')
    ;;
  2) DNS_LINES=$'push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"\n' ;;
  3) DNS_LINES=$'push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"\n' ;;
  4) DNS_LINES=$'push "dhcp-option DNS 208.67.222.222"\npush "dhcp-option DNS 208.67.220.220"\n' ;;
  5) DNS_LINES=$'push "dhcp-option DNS 9.9.9.9"\npush "dhcp-option DNS 149.112.112.112"\n' ;;
esac

# ===== server.conf =====
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
[[ "$MODE" == "2" ]] && echo "duplicate-cn" >> /etc/openvpn/server/server.conf

# ===== маршрутизация =====
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/30-openvpn-forward.conf

IFACE="$(ip route show default 2>/dev/null | awk '/dev/{print $5; exit}')"
[[ -z "${IFACE:-}" ]] && IFACE="$(ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
iptables -C INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT
iptables -C FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# Сохранить правила, обходя баг sed в netfilter-persistent
install -d /etc/iptables
iptables-save  > /etc/iptables/rules.v4 || true
ip6tables-save > /etc/iptables/rules.v6 || true
systemctl enable netfilter-persistent >/dev/null 2>&1 || true

# ===== клиентский шаблон =====
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

# ===== генерация .ovpn =====
gen_client () {
  local NAME="$1" OUT="/root/${NAME}.ovpn"
  cp /etc/openvpn/server/client-common.txt "$OUT"
  {
    echo "<ca>";        cat /etc/openvpn/server/ca.crt; echo "</ca>"
    echo "<cert>";      sed -ne '/BEGIN CERTIFICATE/,$p' "/etc/openvpn/easy-rsa/pki/issued/${NAME}.crt"; echo "</cert>"
    echo "<key>";       cat "/etc/openvpn/easy-rsa/pki/private/${NAME}.key"; echo "</key>"
    echo "<tls-crypt>"; sed -ne '/BEGIN OpenVPN Static key/,$p' /etc/openvpn/server/tc.key; echo "</tls-crypt>"
  } >>"$OUT"
  echo "Создан $OUT"
}

gen_client "$CLIENT"
systemctl enable --now openvpn-server@server.service

# цикл добавления клиентов в “single”
if [[ "$MODE" != "2" && "$AUTO" != "--defaults" ]]; then
  while true; do
    echo "Добавить ещё клиента?  y/N"
    read -r -e -i "N" -p "> " yn
    [[ "${yn:-N}" =~ ^[Yy]$ ]] || break
    read -r -p "Имя клиента: " NEWC; [[ -z "${NEWC:-}" ]] && continue
    EASYRSA_BATCH=1 ./easyrsa build-client-full "$NEWC" nopass
    gen_client "$NEWC"
  done
fi

echo "Готово. Файлы клиентов: /root/*.ovpn"
[[ "$MODE" == "2" ]] && echo "Включён общий конфиг (duplicate-cn). Для безопасности лучше отдельные клиенты."
