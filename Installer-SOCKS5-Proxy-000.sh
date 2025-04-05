#!/bin/bash

function YourBanner(){
 echo -e " Добро пожаловать в установщик SOCKS5!"
 echo -e ""
}


function generate_password() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1
}


source /etc/os-release
if [[ "$ID" != 'ubuntu' ]]; then
 YourBanner
 echo -e "[\e[1;31mError\e[0m] Толлько для Ubuntu ..." 
 exit 1
fi

if [[ $EUID -ne 0 ]];then
 YourBanner
 echo -e "[\e[1;31mError\e[0m] Запусти от root..."
 exit 1
fi

function Installation(){
 cd /root
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
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
 apt-get install wget nano dante-server netcat -y &> /dev/null | echo '[*] Установка SOCKS5...'
 cat <<'EOF'> /etc/danted.conf
logoutput: /var/log/socks.log
internal: 0.0.0.0 port = SOCKSPORT
external: SOCKSINET
socksmethod: SOCKSAUTH
user.privileged: root
user.notprivileged: nobody

client pass {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: error connect disconnect
 }
 
client block {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: connect error
 }
 
socks pass {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: error connect disconnect
 }
 
socks block {
 from: 0.0.0.0/0 to: 0.0.0.0/0
 log: connect error
 }
EOF
 sed -i "s/SOCKSINET/$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)/g" /etc/danted.conf
 sed -i "s/SOCKSPORT/$SOCKSPORT/g" /etc/danted.conf
 sed -i "s/SOCKSAUTH/$SOCKSAUTH/g" /etc/danted.conf
 sed -i '/\/bin\/false/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 systemctl restart danted.service
 systemctl enable danted.service
}
 
function Uninstallation(){
 echo -e '[*] Очистка перед установкой SOCKS5'
 apt-get remove --purge dante-server -y
 rm -rf /etc/danted.conf
 echo -e '[√] Очиства выполнена.'
}

function SuccessMessage(){
 clear
 echo -e ""
 YourBanner
 echo -e "======================"
 echo -e " IP: $(wget -4qO- http://ipinfo.io/ip)"
 echo -e " Port: $SOCKSPORT"
 echo -e " Username: $socksUser"
 echo -e " Password: $socksPass"
 echo -e "======================"
 echo -e ""
 echo -e " Данные для подключения записаны в /root/socks5.txt"
 cat <<EOF> ~/socks5.txt
IP Address: $(wget -4qO- http://ipinfo.io/ip)
Port: $SOCKSPORT
EOF
 if [ "$SOCKSAUTH" == 'username' ]; then
 cat <<EOF>> ~/socks5.txt
Username: $socksUser
Password: $socksPass
EOF
 fi
 echo -e ""
}

clear
YourBanner
SOCKSPORT='8081'
SOCKSAUTH='username'
socksUser='userprxy'
socksPass=$(generate_password)
userdel -r -f $socksUser &> /dev/null
useradd -m -s /bin/false $socksUser
echo -e "$socksPass\n$socksPass\n" | passwd $socksUser &> /dev/null
Uninstallation
Installation
SuccessMessage
exit 1
