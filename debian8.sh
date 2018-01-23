#!/bin/bash
# ******************************************
# Program: Autoscript Setup Vps 2018
# Website: www.AnonymousVpn8.com.my
# Developer: AnonymouVpnTeam
# Nickname: AnonymousVpn8
# Date: 31-12-2017
# Last Updated: 03-01-2018
# ******************************************
# MULA SETUP
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
echo "TUN is not available"
exit 3
fi
echo "
AUTOSCRIPT BY AnonymousVpn8.TK
AMBIL PERHATIAN !!!"
clear
echo "MULA SETUP"
clear
echo "SET TIMEZONE KUALA LUMPUT GMT +8"
ln -fs /usr/share/zoneinfo/Asia/Thailand /etc/localtime;
clear
echo "
ENABLE IPV4 AND IPV6
SILA TUNGGU SEDANG DI SETUP
"
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear
echo "
MEMBUANG SPAM PACKAGE
"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
clear
echo "
"
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt-get update;
apt-get -y autoremove;
apt-get -y install wget curl;
echo "
"
# text gambar
apt-get install boxes
# color text
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "https://raw.githubusercontent.com/khungphat84/afq8298/master/.bashrc"
# install lolcat
sudo apt-get -y install ruby
sudo gem install lolcat
# script
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/khungphat84/noname/master/common-password"
chmod +x /etc/pam.d/common-password
# fail2ban & exim & protection
apt-get -y install fail2ban sysv-rc-conf dnsutils dsniff zip unzip;
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip;unzip master.zip;
cd ddos-deflate-master && ./install.sh
service exim4 stop;sysv-rc-conf exim4 off;
# webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
# dropbear
apt-get -y install dropbear
wget -O /etc/default/dropbear "https://raw.githubusercontent.com/khungphat84/noname/master/dropbear"
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
# squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/khungphat84/noname/master/squid.conf"
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/khungphat84/noname/master/squid.conf"
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid/squid.conf
# openvpn
apt-get -y install openvpn
wget -O /etc/openvpn/openvpn.tar "https://raw.githubusercontent.com/khungphat84/noname/master/openvpn.tar"
cd /etc/openvpn/;tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/rc.local "https://raw.githubusercontent.com/khungphat84/noname/master/rc.local";chmod +x /etc/rc.local
#wget -O /etc/iptables.up.rules "https://raw.githubusercontent.com/macisvpn/inject-69/master/iptables.up.rules"
#sed -i "s/ipserver/$myip/g" /etc/iptables.up.rules
#iptables-restore < /etc/iptables.up.rules
# nginx
apt-get -y install nginx php-fpm php-mcrypt php-cli libexpat1-dev libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/php/7.0/fpm/pool.d/www.conf "https://raw.githubusercontent.com/khungphat84/noname/master/www.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by inject69 | telegram @AnonymousVpn8 | website AnonymousVpn8.tk</pre>" > /home/vps/public_html/index.php
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "http://autoscriptnobita.tk/rendum/vps.conf"
sed -i 's/listen = \/var\/run\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
# etc
wget -O /home/vps/public_html/client.ovpn "https://raw.githubusercontent.com/khungphat84/noname/master/client.ovpn"
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
useradd -m -g users -s /bin/bash archangels
echo "7C22C4ED" | chpasswd
echo "UPDATE DAN INSTALL SIAP 99% MOHON SABAR"
cd;rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;
# install badvpn
apt-get -y install cmake make gcc
wget https://raw.githubusercontent.com/khungphat84/noname/master/badvpn-1.999.127.tar.bz2
tar xf badvpn-1.999.127.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.127 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd
# ssssslll
apt-get update
apt-get upgrade
apt-get install stunnel4
wget -O /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/khungphat84/noname/master/stunnel.conf"
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart
# download script
cd
wget -O /usr/bin/motd "https://raw.githubusercontent.com/khungphat84/afq8298/master/motd"
wget -O /usr/bin/benchmark "https://raw.githubusercontent.com/khungphat84/afq8298/master/benchmark.sh"
wget -O /usr/bin/speedtest "https://raw.githubusercontent.com/khungphat84/afq8298/master/speedtest_cli.py"
wget -O /usr/bin/ps-mem "https://raw.githubusercontent.com/khungphat84/afq8298/master/ps_mem.py"
wget -O /usr/bin/dropmon "https://raw.githubusercontent.com/khungphat84/afq8298/master/dropmon.sh"
wget -O /usr/bin/menu "https://raw.githubusercontent.com/khungphat84/afq8298/master/menu.sh"
wget -O /usr/bin/user-active-list "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-active-list.sh"
wget -O /usr/bin/user-add "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-add.sh"
wget -O /usr/bin/user-add-pptp "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-add-pptp.sh"
wget -O /usr/bin/user-del "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-del.sh"
wget -O /usr/bin/disable-user-expire "https://raw.githubusercontent.com/khungphat84/afq8298/master/disable-user-expire.sh"
wget -O /usr/bin/delete-user-expire "https://raw.githubusercontent.com/khungphat84/afq8298/master/delete-user-expire.sh"
wget -O /usr/bin/banned-user "https://raw.githubusercontent.com/khungphat84/afq8298/master/banned-user.sh"
wget -O /usr/bin/unbanned-user "https://raw.githubusercontent.com/khungphat84/afq8298/master/unbanned-user.sh"
wget -O /usr/bin/user-expire-list "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-expire-list.sh"
wget -O /usr/bin/user-gen "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-gen.sh"
wget -O /usr/bin/userlimit.sh "https://raw.githubusercontent.com/khungphat84/afq8298/master/userlimit.sh"
wget -O /usr/bin/userlimitssh.sh "https://raw.githubusercontent.com/khungphat84/afq8298/master/userlimitssh.sh"
wget -O /usr/bin/user-list "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-list.sh"
wget -O /usr/bin/user-login "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-login.sh"
wget -O /usr/bin/user-pass "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-pass.sh"
wget -O /usr/bin/user-renew "https://raw.githubusercontent.com/khungphat84/afq8298/master/user-renew.sh"
wget -O /usr/bin/clearcache.sh "https://raw.githubusercontent.com/khungphat84/afq8298/master/clearcache.sh"
wget -O /usr/bin/bannermenu "https://raw.githubusercontent.com/khungphat84/afq8298/master/bannermenu"
cd
#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/
wget -O /root/passwd "https://raw.githubusercontent.com/khungphat84/afq8298/master/passwd.sh"
chmod +x /root/passwd
echo "01 23 * * * root /root/passwd" > /etc/cron.d/passwd
echo "*/30 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
#echo "00 01 * * * root echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a" > /etc/cron.d/clearcacheram3swap
echo "*/30 * * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1
cd
chmod +x /usr/bin/motd
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/clearcache.sh
chmod +x /usr/bin/bannermenu
cd

clear
# restart service
service ssh restart
service openvpn restart
service dropbear restart
service nginx restart
service php7.0-fpm restart
service webmin restart
service squid restart
service fail2ban restart
clear
# SELASAI SUDAH BOSS! ( AnonymousVpn8.Tk )
echo "========================================"  | tee -a log-install.txt
echo "Service Autoscript AnonymousVpn8 ( AnonymousVpn8 2017)"  | tee -a log-install.txt
echo "----------------------------------------"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "nginx : http://$myip:80"   | tee -a log-install.txt
echo "Webmin : http://$myip:10000/"  | tee -a log-install.txt
echo "Squid3 : 1111"  | tee -a log-install.txt
echo "OpenSSH : 22"  | tee -a log-install.txt
echo "Dropbear : 442"  | tee -a log-install.txt
echo "OpenVPN  : TCP 1194 (DAPATKAN OVPN DARI SAYA)"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "Timezone : Asia/Kuala_Lumpur"  | tee -a log-install.txt
echo "Menu : type menu to check menu script"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------------------------------------"
echo "LOG INSTALL  --> /root/log-install.txt"
echo "----------------------------------------"
echo "========================================"  | tee -a log-install.txt
echo "      PLEASE REBOOT TO TAKE EFFECT !"
echo "========================================"  | tee -a log-install.txt
cat /dev/null > ~/.bash_history && history -c
