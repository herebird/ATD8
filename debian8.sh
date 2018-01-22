#!/bin/bash

if [ $USER != 'root' ]; then
	echo "Sorry, for run the script please using root user"
	exit
fi

# check OS
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

myip=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	myip=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#source file
	source="https://goo.gl/yTmQPm"

# go to root
cd

#password
clear
 echo ""
          echo -e "\e[031;1m     
                         
                =============== OS-32 & 64-bit ================
                ♦                                             ♦
                ♦     AUTOSCRIPT CREATED BY เฮียเบิร์ด แงะตลอด   ♦
                ♦       -----------About Us------------       ♦ 
                ♦            Telp : 097-026-7262              ♦
                ♦         { VPN / SSH / OCS PANEL }           ♦ 
                ♦       http://facebook.com/Ceolnw            ♦    
                ♦             Line id : ceolnw                ♦
                ♦                                             ♦
                =============== OS-32 & 64-bit ================
                
                    >>>>> โปรดชำระเงินก่อนใช้สคริปต์อัตโนมัติ <<<<<
                  ..........................................
                  .         ราคา: 50 บาท = 1IP             .
                  .        ***********************         .
                  .        True Wallet Account             .
                  .        =======================         .
                  .        Phone : 097-026-7262            .
                  .        Name  : HERE BIRD LNWSHOP       .
                  ..........................................   
                                      
                           Thank You For Choice Us"
			
	echo ""
	echo -e "\e[034;1m----SCRIPT V.1 FREE"
	echo ""
	echo -e "\e[032;1m ( ใส่รหัสผ่านติดตั้ง... )"
	echo ""
read -p "๏๏๏โปรดใส่รหัสสำหรับติดตั้งสคลิปนี้.. : " passwds
wget -q -O /usr/bin/pass http://27.254.81.20/~com/pass.txt
if ! grep -w -q $passwds /usr/bin/pass; then
clear
echo ""
echo ""
echo " เสียใจด้วย รหัสผิดว่ะ ถ้าไม่มีรหัสติดต่อแอดมินฯ เฮียเบิร์ด"
echo ""
echo " เด้งไปเลยเฟสนี้แน่นอน : www.facebook.com/ceonw"
echo ""
echo ""
rm /usr/bin/pass
rm debian7.sh
exit
fi

clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com 
[√] Connect...Setting vps
[√] กำลังเริ่มติดตั้ง : vpsconfig..... [ OK !! ]
----------------------------------------------
 "
 sleep 10
# GO TO BOXES | www.fb.com/ceolnw
apt-get install boxes

# INSTALL RUBY | www.fb.com/ceolnw
sudo apt-get install ruby
sudo gem install lolcat

# SETUP BASHRC | www.fb.com/ceolnw
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc $source/debian7/.bashrc



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Requirement
[√] กำลังเริ่มติดตั้ง : Requirement..... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# UPDATE SYSTEM | www.fb.com/ceolnw
if [ ! -e /usr/bin/curl ]; then
  apt-get -y update; apt-get -y upgrade; apt-get -y install curl;
fi



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Disable IPv6
[√] กำลังเริ่มปิด : IPv6..... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# DISABLE IPV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...DNS Server IPv4
[√] กำลังเริ่มติดตั้ง : DNS IPv4..... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# ADD DNS SERVER IPV4 | www.fb.com/ceolnw
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Wget Curl
[√] กำลังเริ่มติดตั้ง : Wget Curl..... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL WGET AND CURL | www.fb.com/ceolnw
apt-get update; apt-get -y install wget curl;



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Time zone
[√] กำลังเริ่มติดตั้ง : Time GMT +7.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET TIME GMT +7 | www.fb.com/ceolnw
ln -fs /usr/share/zoneinfo/Asia/Bangkok /etc/localtime



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Bangner SSH
[√] กำลังเริ่มติดตั้ง : Bangner SSH.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET BANNER SSH | www.fb.com/ceolnw
echo "Banner /bannerssh" >> /etc/ssh/sshd_config
cat > /bannerssh <<END0

<BR><font color="#00B146">================</font></BR> <BR><font color='#860000'><h3>NO SPAM !!!</h3></BR></font> <BR><font color='#1E90FF'><h3>NO DDOS !!!</h3></BR></font> <BR><font color='#FF0000'><h3>NO HACKING !!!</h3></BR></font> <BR><font color='#008080'><h3>NO CARDING !!!</h3></BR></font> <BR><font color='#BA55D3'><h3>NO CRIMINAL CYBER !!!</h3></BR></font> <BR><font color='#32CD32'><h3>MAX LOGIN 2 DEVICE !!!</h3></BR></font> <BR><font color="#00B146">================</font></BR> <BR><font color="#0082D8"><h3>★ w w w . เ ฮี ย เ บิ ร์ ด . c o m ★</h3> </font></BR> <BR><font color="#00B146">================</font></BR>
END0



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Locale
[√] กำลังเริ่มติดตั้ง : Locale.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET LOCALE
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
service ssh restart



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com 
[√] Connect...Repo
[√] กำลังเริ่มติดตั้ง : Repo.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET REPO
cat > /etc/apt/sources.list <<END2
deb http://cdn.debian.net/debian wheezy main contrib non-free
deb http://security.debian.org/ wheezy/updates main contrib non-free
deb http://packages.dotdeb.org wheezy all
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Unused
[√] กำลังเริ่มนำออก : Unsed.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# REMOVE UNUSE | www.fb.com/ceolnw
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*;
apt-get -y remove sendmail*;


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Update
[√] กำลังเริ่มติดตั้ง : Update.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# UPDATE
apt-get update; apt-get -y upgrade;


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...WebServer
[√] กำลังเริ่มติดตั้ง : WebServer.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL WEBSERVER | www.fb.com/ceolnw
apt-get -y install nginx; apt-get -y install php5-fpm; apt-get -y install php5-cli;


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Essential
[√] กำลังเริ่มติดตั้ง : Essential.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL ESSENTIAL PACKAGE | www.fb.com/ceolnw
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter; apt-get -y install build-essential;


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Exim
[√] กำลังเริ่มปิด : Exim.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# DISABLE EXIM | www.fb.com/ceolnw
service exim4 stop
sysv-rc-conf exim4 off


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Apt-file
[√] กำลังเริ่มติดตั้ง : Apt-file.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# UPDATE APT-FILE | www.fb.com/ceolnw
apt-file update;


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Vnstat
[√] กำลังเริ่มตั้งค่า : Vnstat.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SETTING VNSTAT | www.fb.com/ceolnw
vnstat -u -i eth0
service vnstat restart


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...ScreenFetch
[√] กำลังเริ่มติดตั้ง : ScreenFetch.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL SCREENFETCH | www.fb.com/ceolnw
cd
wget -O /usr/bin/screenfetch "https://dl.dropboxusercontent.com/s/ycyegwijkdekv4q/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...WebServer
[√] กำลังเริ่มติดตั้ง : WebServer.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL WEBSERVER | www.fb.com/ceolnw
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
wget -O /home/vps/public_html/index.html "https://dl.dropboxusercontent.com/s/rnlmnk0grb6p37s/index"
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


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...OpenVPN
[√] กำลังเริ่มติดตั้ง : OpenVPN.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL OPENVPN | www.fb.com/ceolnw
apt-get -y install openvpn; apt-get -y install iptables; apt-get -y install openssl;
cp -R /usr/share/doc/openvpn/examples/easy-rsa/ /etc/openvpn


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Easy-rsa
[√] กำลังเริ่มติดตั้ง : Easy-rsa.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL EASY-RSA | www.fb.com/ceolnw
if [[ ! -d /etc/openvpn/easy-rsa/2.0/ ]]; then
	wget --no-check-certificate -O ~/easy-rsa.tar.gz https://dl.dropboxusercontent.com/s/cqhoz85lxvczqr2/easy-rsa-2.2.2.tar.gz
    tar xzf ~/easy-rsa.tar.gz -C ~/
    mkdir -p /etc/openvpn/easy-rsa/2.0/
    cp ~/easy-rsa-2.2.2/easy-rsa/2.0/* /etc/openvpn/easy-rsa/2.0/
    rm -rf ~/easy-rsa-2.2.2
    rm -rf ~/easy-rsa.tar.gz
fi
cd /etc/openvpn/easy-rsa/2.0/



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Really Error
[√] กำลังเริ่มตั้งค่า : Really Error.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET REALLY ERROR | www.fb.com/ceolnw
cp -u -p openssl-1.0.0.cnf openssl.cnf



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Replace Bits
[√] กำลังเริ่มตั้งค่า : Replace Bits.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET REPLACEBITS | www.fb.com/ceolnw
sed -i 's|export KEY_SIZE=1024|export KEY_SIZE=2048|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="TH"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="Thailand"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="FB Tae.TaRuMa"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="WwW.BYVPN.NeT"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="Tae.TaRuMa@Gmail.com"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_EMAIL=mail@host.domain|export KEY_EMAIL=Tae.TaRuMa@Gmail.com|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_CN=changeme|export KEY_CN="BYVPN.NET"|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_NAME=changeme|export KEY_NAME=BYVPN.NET|' /etc/openvpn/easy-rsa/2.0/vars
sed -i 's|export KEY_OU=changeme|export KEY_OU=BYVPN.NET|' /etc/openvpn/easy-rsa/2.0/vars



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...PKI
[√] กำลังเริ่มติดตั้ง : Create a PKI.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# CREATE PKI | www.fb.com/ceolnw
. /etc/openvpn/easy-rsa/2.0/vars
. /etc/openvpn/easy-rsa/2.0/clean-all



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Certificate
[√] กำลังเริ่มติดตั้ง : Create a Certificate.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# CREATE CERTIFICATE | www.fb.com/ceolnw
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --initca $*



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Key Server
[√] กำลังเริ่มติดตั้ง : Create a Key Server.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# CREATE KEY SERVER | www.fb.com/ceolnw
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --server server



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Setting KEY CN
[√] กำลังเริ่มติดตั้ง : KEY CN.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SETTING KEY CN | www.fb.com/ceolnw
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" client



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...DH Params
[√] กำลังเริ่มติดตั้ง : DH Params.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# DH PARAMS | www.fb.com/ceolnw
. /etc/openvpn/easy-rsa/2.0/build-dh



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Setting Server
[√] กำลังเริ่มตั้งค่า : Server.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SETTING SERVER | www.fb.com/ceolnw
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



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...OpenVPN
[√] กำลังเริ่มติดตั้ง : OpenVPN.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# CREATE OPENVPN CONFIG | www.fb.com/ceolnw
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/client.ovpn <<-END
## [+] ยินดีต้อนรับเข้าสู่ WWW.เฮียเบิร์ด.COM เซิร์ฟเวอร์ มาตรฐาน ราคายุติธรรม
##
## [+] เกี่ยวกับผู้พัฒนา
##
## [+] โดย : ธนกร เนียนทศาสตร์ (เฮียเบิร์ด)
##
## [+] เบอร์โทร : 097-026-7262
##
## [+] ไอดีลาย : Ceolnw
##
## [+] เฟชบุ๊ค : https://www.facebook.com/ceolnw
##
## [+] แฟนเพจ : https://www.facebook.com/ceolnw
##
## [+] เว็บไซต์ : https://www.เฮียเบิร์ด.com
##
## [+] ลิขสิทธิ์ : © Copyright 2018 เฮียเบิร์ด.com all rights reserved.
client
proto tcp
dev tun
remote เฮียเบิร์ด.com 9999 udp
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



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...IPv4 Forward
[√] กำลังเริ่มติดตั้ง : IPv4 Forward.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SET IPV4 FORWARD | www.fb.com/ceolnw
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...OpenVPN
[√] กำลังเริ่ม : Restart OpenVPN.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# RESTART OPENVPN | www.fb.com/ceolnw
/etc/init.d/openvpn restart



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...PPTP
[√] กำลังเริ่มติดตั้ง : PPTP.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL PPTP | www.fb.com/ceolnw
apt-get -y install pptpd;
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



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...badvpn
[√] กำลังเริ่มติดตั้ง : badvpn.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL BADVPN | www.fb.com/ceolnw
wget -O /usr/bin/badvpn-udpgw "https://dl.dropboxusercontent.com/s/yj7gj6melefqiwc/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://dl.dropboxusercontent.com/s/gqd1rjy1nw0yyd8/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...mrtg
[√] กำลังเริ่มติดตั้ง : mrtg.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL MRTG | www.fb.com/ceolnw
wget -O /etc/snmp/snmpd.conf "https://dl.dropboxusercontent.com/s/h43jmsru1i5prkf/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://dl.dropboxusercontent.com/s/xlm1ybd8miutqs6/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://dl.dropboxusercontent.com/s/sek48u10pafav3b/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then
mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Ssh
[√] กำลังเริ่มติดตั้ง : Port Ssh.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SETTING PORT SSH | www.fb.com/ceolnw
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...DropBear
[√] กำลังเริ่มติดตั้ง : DropBear.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restar



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Vnstat Gui
[√] กำลังเริ่มติดตั้ง : Vnstat Gui.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL VBSTAT GUI | www.fb.com/ceolnw
cd /home/vps/public_html/
wget https://dl.dropboxusercontent.com/s/1rzq3xbxg1mbwli/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
rm /home/vps/public_html/vnstat/index.php
wget -O /home/vps/public_html/vnstat/index.php "https://dl.dropboxusercontent.com/s/0kj4lg2yuo90qmu/vnstat"
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...fail2ban
[√] กำลังเริ่มติดตั้ง : fail2ban.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL FAIL2BAN | www.fb.com/ceolnw
apt-get -y install fail2ban;
service fail2ban restart



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Squid3
[√] กำลังเริ่มติดตั้ง : Squid3.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# INSTALL SQUID3 | www.fb.com/ceolnw
apt-get -y install squid3;
cat > /etc/squid3/squid.conf <<-END
## [+] ยินดีต้อนรับเข้าสู่ WWW.เฮียเบิร์ด.COM เซิร์ฟเวอร์ มาตรฐาน ราคายุติธรรม
##
## [+] เกี่ยวกับผู้พัฒนา
##
## [+] โดย : ธนกร เนียนทศาสตร์ (เฮียเบิร์ด)
##
## [+] เบอร์โทร : 097-026-7262
##
## [+] ไอดีลาย : Ceolnw
##
## [+] เฟชบุ๊ค : https://www.facebook.com/ceolnw
##
## [+] แฟนเพจ : https://www.facebook.com/ceolnw
##
## [+] เว็บไซต์ : https://www.เฮียเบิร์ด.com
##
## [+] ลิขสิทธิ์ : © Copyright 2018 เฮียเบิร์ด.com all rights reserved.
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


clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...IPtables
[√] กำลังเริ่มติดตั้ง : IPtables.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# SETTING IPTAPLES | www.fb.com/ceolnw
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



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Script
[√] กำลังเริ่มติดตั้ง : Script.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# DOWNLOAD SCRIPT | www.fb.com/ceolnw
cd
wget https://dl.dropboxusercontent.com/s/vcd7jdd7i2bg5bd/install-premiumscript.sh -O - -o /dev/null|sh



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...Finalisasi
[√] กำลังเริ่มติดตั้ง : Finalisasi.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 5
# FINALISASI | www.fb.com/ceolnw
apt-get -y autoremove;
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
rm /root/debian8.sh
rm -f /root/debian8.sh



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...History
[√] กำลังเริ่มเคลีย : History.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 3
# CLEARING HISTORY | www.fb.com/ceolnw
history -c



clear
echo "
----------------------------------------------
[√] Source : เฮียเบิร์ด.com
[√] Connect...เสร็จสิ้นการติดตั้ง
[√] กำลังเรียกข้อมูล : Info.... [ OK !! ]
----------------------------------------------
 " | lolcat
 sleep 5
# INFO | www.fb.com/ceolnw
clear
echo "----------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "INFROMATION SERVER"  | tee -a log-install.txt
echo "   - TIMEZONE    : Asia/Bangkok (GMT +7)"  | tee -a log-install.txt
echo "   - FAIL2BAN    : [on]"  | tee -a log-install.txt
echo "   - IPTABLES    : [on]"  | tee -a log-install.txt
echo "   - AUTO-REBOOT : [off]"  | tee -a log-install.txt
echo "   - IPV6        : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "INFORMATION APLINK & PORT"  | tee -a log-install.txt
echo "   - OPENVPN     : 1194 "  | tee -a log-install.txt
echo "   - OPENSSH     : 22,143"  | tee -a log-install.txt
echo "   - DROPBEAR    : 109,110,443"  | tee -a log-install.txt
echo "   - SQUID PROXY : 80,3128,8000,8080 (limit to IP Server)"  | tee -a log-install.txt
echo "   - BADVPN      : 7300"  | tee -a log-install.txt
echo "   - NGINX       : 81"  | tee -a log-install.txt
echo "   - PPTP VPN    : 1732"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "ข้อมูลเครื่องมือในเซิร์ฟเวอร์"  | tee -a log-install.txt
echo "   - HTOP"  | tee -a log-install.txt
echo "   - IFTOP"  | tee -a log-install.txt
echo "   - MTR"  | tee -a log-install.txt
echo "   - NETHOGS"  | tee -a log-install.txt
echo "   - SCREENFETCH"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "ข้อมูลพรีเมี่ยมสคริปต์"  | tee -a log-install.txt
echo "   คำสั่งเพื่อแสดงรายการคำสั่ง: MENU"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   คำอธิบายสคริปต์และการตั้งค่า VPS"| tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Download Config  : http://$MYIP:81/client.ovpn"  | tee -a log-install.txt
echo "   - Webmin           : http://$MYIP:10000/"  | tee -a log-install.txt
echo "   - Vnstat           : http://$MYIP:81/vnstat/"  | tee -a log-install.txt
echo "   - MRTG             : http://$MYIP:81/mrtg/"  | tee -a log-install.txt
echo "   - Log Install      : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------- สคริปออโต้ www.เฮียเบิร์ด.com ขอบคุณครับ------------"
