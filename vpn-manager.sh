# 1) создать файл из кода ниже
cat > vpn-manager.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

AUTO="${1:-}"   # --defaults = без вопросов
[[ $EUID -eq 0 ]] || { echo "Нужен root"; exit 1; }
command -v apt >/dev/null || { echo "Нужен Debian/Ubuntu"; exit 1; }

ask(){ local v="$1" d="$2" p="$3"; if [[ "$AUTO" == "--defaults" ]]; then printf -v "$v" '%s' "$d"; echo "$p [$d]: $d"; else read -e -i "$d" -p "$p [$d]: " "$v"; [[ -z "${!v}" ]] && printf -v "$v" '%s' "$d"; fi; }
menu_proto(){ echo "Протокол:"; echo "  1) UDP"; echo "  2) TCP"; if [[ "$AUTO" == "--defaults" ]]; then CH="1"; echo "Ваш выбор [1]: 1"; else read -e -i "1" -p "Ваш выбор [1]: " CH; fi; case "${CH:-1}" in 1) PROTO="udp";; 2) PROTO="tcp";; *) PROTO="udp";; esac; }
menu_dns(){ echo "DNS:"; echo "  1) System"; echo "  2) Unbound (локальный)"; echo "  3) Cloudflare"; echo "  4) Google"; echo "  5) OpenDNS"; echo "  6) Quad9"; if [[ "$AUTO" == "--defaults" ]]; then DNS_CH="1"; echo "Ваш выбор [1]: 1"; else read -e -i "1" -p "Ваш выбор [1]: " DNS_CH; fi; DNS_CH=${DNS_CH:-1}; }
menu_mode(){ echo "Режим клиентов:"; echo "  1) Каждый свой конфиг (рекомендуется)"; echo "  2) Мульти (duplicate-cn, небезопасно)"; if [[ "$AUTO" == "--defaults" ]]; then MODE="1"; echo "Ваш выбор [1]: 1"; else read -e -i "1" -p "Ваш выбор [1]: " MODE; fi; MODE=${MODE:-1}; }
iface(){ ip route show default 2>/dev/null | awk '/dev/{print $5; exit}' || ip route get 1.1.1.1 | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
pubip(){ ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || hostname -I | awk '{print $1}'; }

mk_client(){
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

install_unbound(){
  apt install -y unbound
  cat >/etc/unbound/unbound.conf.d/openvpn.conf <<'UCONF'
server:
  interface: 10.8.0.1
  access-control: 10.8.0.0/24 allow
  hide-identity: yes
  hide-version: yes
  prefetch: yes
UCONF
  systemctl enable --now unbound
}

install_openvpn(){
  local RAND_PORT PORT PROTO DNS_CH PUBLIC_IP MODE CLIENT
  RAND_PORT="$(shuf -i 20000-60000 -n1)"
  ask PORT "$RAND_PORT" "Порт"; menu_proto; menu_dns
  ask PUBLIC_IP "$(pubip)" "Публичный IPv4 для клиентов"; menu_mode
  [[ "$MODE" == "2" ]] && ask CLIENT "shared" "Имя общего клиента" || ask CLIENT "client1" "Имя первого клиента"

  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y openvpn easy-rsa iptables-persistent ca-certificates curl

  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow "$PORT/$PROTO" || true; fi

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
  openvpn --genkey secret /etc/openvpn/server/tc.key

  [[ "$DNS_CH" == "2" ]] && install_unbound
  DNS_LINES=""
  case "$DNS_CH" in
    1) RESOLVCONF='/etc/resolv.conf'; [[ -f /run/systemd/resolve/resolv.conf ]] && RESOLVCONF='/run/systemd/resolve/resolv.conf'; while read -r ns; do DNS_LINES+="push \"dhcp-option DNS $ns\"\n"; done < <(grep -v '#' "$RESOLVCONF" | awk '/nameserver/{print $2}') ;;
    2) DNS_LINES=$'push "dhcp-option DNS 10.8.0.1"\n' ;;
    3) DNS_LINES=$'push "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 1.0.0.1"\n' ;;
    4) DNS_LINES=$'push "dhcp-option DNS 8.8.8.8"\npush "dhcp-option DNS 8.8.4.4"\n' ;;
    5) DNS_LINES=$'push "dhcp-option DNS 208.67.222.222"\npush "dhcp-option DNS 208.67.220.220"\n' ;;
    6) DNS_LINES=$'push "dhcp-option DNS 9.9.9.9"\npush "dhcp-option DNS 149.112.112.112"\n' ;;
  esac

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

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/30-openvpn-forward.conf

  IFACE="$(iface)"
  iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
  iptables -C INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -p ${PROTO} --dport ${PORT} -j ACCEPT
  iptables -C FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
  iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  install -d /etc/iptables
  iptables-save  > /etc/iptables/rules.v4 || true
  ip6tables-save > /etc/iptables/rules.v6 || true
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true

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
verify-x509-name server name
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
key-direction 1
verb 3
EOF

  systemctl enable --now openvpn-server@server.service
  mk_client "$CLIENT"
  echo "Готово. /root/${CLIENT}.ovpn"
  [[ "$MODE" == "2" ]] && echo "Включён мульти-конфиг (duplicate-cn)."
}

add_client(){
  [[ -d /etc/openvpn/easy-rsa ]] || { echo "Сначала установка."; exit 1; }
  read -rp "Имя клиента: " NAME
  cd /etc/openvpn/easy-rsa
  EASYRSA_BATCH=1 ./easyrsa build-client-full "$NAME" nopass
  mk_client "$NAME"
}

revoke_client(){
  [[ -d /etc/openvpn/easy-rsa ]] || { echo "Сначала установка."; exit 1; }
  read -rp "Имя клиента для отзыва: " NAME
  cd /etc/openvpn/easy-rsa
  ./easyrsa --batch revoke "$NAME"
  EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
  cp pki/crl.pem /etc/openvpn/server/crl.pem
  systemctl restart openvpn-server@server
  echo "Отозван $NAME"
}

uninstall_openvpn(){
  systemctl disable --now openvpn-server@server.service || true
  rm -rf /etc/openvpn /etc/iptables/rules.v4 /etc/iptables/rules.v6
  echo "Удалено."
}

main_menu(){
  echo "=== VPN Manager ==="
  echo "  1) Установить OpenVPN"
  echo "  2) Добавить клиента"
  echo "  3) Отозвать клиента"
  echo "  4) Удалить OpenVPN"
  echo "  5) Выход"
  read -rp "Выбор [1-5]: " op
  case "${op:-1}" in
    1) install_openvpn ;;
    2) add_client ;;
    3) revoke_client ;;
    4) uninstall_openvpn ;;
    5) exit 0 ;;
    *) echo "Неверно"; exit 1 ;;
  esac
}
main_menu
EOF
# 2) дать права и запустить
chmod +x vpn-manager.sh
sudo ./vpn-manager.sh
