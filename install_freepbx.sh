#!/bin/bash

# Обновление системы и установка зависимостей
apt-get update -y
apt-get upgrade -y
apt-get install unzip git gnupg2 curl libnewt-dev libssl-dev libncurses5-dev subversion libsqlite3-dev build-essential libjansson-dev libxml2-dev uuid-dev subversion -y

# Установка Asterisk
cd /usr/src
wget http://downloads.asterisk.org/pub/telephony/asterisk/asterisk-18-current.tar.gz
tar -xvzf asterisk-18-current.tar.gz
cd asterisk-18.*
contrib/scripts/get_mp3_source.sh
contrib/scripts/install_prereq install
./configure
make menuselect  # Этот шаг требует ручного ввода для выбора модулей.
make -j2
make install
make samples
make config
ldconfig

# Настройка Asterisk
groupadd asterisk
useradd -r -d /var/lib/asterisk -g asterisk asterisk
usermod -aG audio,dialout asterisk
chown -R asterisk.asterisk /etc/asterisk
chown -R asterisk.asterisk /var/{lib,log,spool}/asterisk
chown -R asterisk.asterisk /usr/lib/asterisk
sed -i 's/^;AST_USER="asterisk"/AST_USER="asterisk"/' /etc/default/asterisk
sed -i 's/^;AST_GROUP="asterisk"/AST_GROUP="asterisk"/' /etc/default/asterisk
sed -i 's/^;runuser = asterisk/runuser = asterisk/' /etc/asterisk/asterisk.conf
sed -i 's/^;rungroup = asterisk/rungroup = asterisk/' /etc/asterisk/asterisk.conf
systemctl restart asterisk
sed -i 's";\[radius\]"\[radius\]"g' /etc/asterisk/cdr.conf
sed -i 's";radiuscfg => /usr/local/etc/radiusclient-ng/radiusclient.conf"radiuscfg => /etc/radcli/radiusclient.conf"g' /etc/asterisk/cdr.conf
sed -i 's";radiuscfg => /usr/local/etc/radiusclient-ng/radiusclient.conf"radiuscfg => /etc/radcli/radiusclient.conf"g' /etc/asterisk/cel.conf
systemctl restart asterisk

# Установка FreePBX
apt-get install software-properties-common -y
add-apt-repository ppa:ondrej/php -y
apt-get update -y
apt-get install apache2 mariadb-server libapache2-mod-php7.2 php7.2 php-pear php7.2-cgi php7.2-common php7.2-curl php7.2-mbstring php7.2-gd php7.2-mysql php7.2-bcmath php7.2-zip php7.2-xml php7.2-imap php7.2-json php7.2-snmp -y
cd /usr/src
wget http://mirror.freepbx.org/modules/packages/freepbx/freepbx-15.0-latest.tgz
tar -xvzf freepbx-15.0-latest.tgz
cd freepbx
apt-get install nodejs npm -y
./install -n
fwconsole ma install pm2
sed -i 's/^\(User\|Group\).*/\1 asterisk/' /etc/apache2/apache2.conf
sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
sed -i 's/\(^upload_max_filesize = \).*/\120M/' /etc/php/7.2/apache2/php.ini
sed -i 's/\(^upload_max_filesize = \).*/\120M/' /etc/php/7.2/cli/php.ini
a2enmod rewrite
systemctl restart apache2

echo "Установка FreePBX завершена."
