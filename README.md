---
title: Linux
description: TW Skills
tags: skills
---

# Overview

This is a linux documents use debian 10

**Linux Distribution :** Debian 10

![Debian][logo]

[TOC]

---

# Configuration

## Timezone

Change timezone

```bash
sudo timedatectl set-timezone Asia/Taipei
```

Show timezone

```bash
ls -l /etc/localtime
```

## Host

Change hostname

```bash
sudo vim /etc/hostname
```

## Users

### ADD user

`sudo useradd -m -d "/home/username" -s /bin/bash username`

### Remove user

`sudo userdel -r username` 

### New group

`sudo groupadd group_kawaii_no_joshi_shougakusei_name`

### Change Folder group

```bash
sudo chgrp group_name folder_name
```

### Change Password via shell script

```bash
echo "username:password" | chpasswd
```

## Network

File: `/etc/network/interfaces`

force to clean ip of interface

```
ip addr flush dev eth0  
```

### DHCP (Dynamic Host Configuration Protocol)

renew a dhcp ip

```
dhclient
```

```
auto eth0
    iface eth0 inet dhcp 
```

### Static

```
iface eth0 inet static
    address 192.168.0.7
    netmask 255.255.255.0
    gateway 192.168.0.254 
```

### PPPoE

```
auto dsl-provider
iface dsl-provider inet ppp
pre-up /sbin/ifconfig eth0 up # line maintained by pppoeconf
provider dsl-provider

auto eth0
iface eth0 inet manual 
```

### DNS

Edit `/etc/resolv.conf`

```
nameserver 8.8.8.8
```

## Link aggregation

```bash
sudo apt install ifenslave # Install ifenslave
sudo modprobe bonding
sudo echo 'bonding' >> /etc/modules
```

Add bond0 in  `/etc/network/interfaces`

```
auto bond0
iface bond0 inet dhcp
    bond-mode 1
    bond-primary eth0
    bond-slaves eth0 eth1
    bond-millmon 100
    bond-downdelay 400
    bond-updelat 800
```


```bash
sudo ifdown eth0 eth1
sudo systemctl restart networking
```

## NTP Time setting

```bash
sudo apt install ntpdate # Install ntpdate tool
sudo ntpdate [ntp server ip]
sudo hwclock -w # Write time into BIOS
```

## Crontab

### Basic Configuration

Allow some users use crontab

Edit `/etc/cron.allow`

```
User1
User2
```

Deny some users use crontab

Edit `/etc/cron.deny`

```
User3
User4
```

Allow > Deny

### List jobs

```bash
crontab -l
```

### Remove all jobs

```bash
cromtab -r
```

### Add jobs

Edit User's crontab

```bash
crontab -e
```

or Edit System's crontb in `/etc/crontab` using root

Format

```
* * * * * command
| | | | |
| | | | ----- Day of week (0 - 7) (Sunday=0 or 7)
| | | ------- Month (1 - 12)
| | --------- Day of month (1 - 31)
| ----------- Hour (0 - 23)
------------- Minute (0 - 59)

* 
n,m n and m
n-m n to m
/n every n

```

Example

```
* */12 * * * shutdown -r now
# every 12 hours restart computer
```

### Other crontab command

```bash
@reboot command # run command in reboot

@yearly command # run command every year same as 0 0 1 1 * command

@monthly command # run command every month same as 0 0 1 * * command

@weekly command # run command every week same as 0 0 * * 1 command

@daily command # run command every day same as 0 0 * * * command

@hourly command # run command every hour same as 0 * * * * command
```

## Quota

- Limiting the disk space

### Basic setting

Edit `/etc/fstab`

```bash
# Original configuration
/dev/sda2    /home        ext4        defaults            1        1

# Add usrquota
/dev/sda2    /home        ext4        defaults,usrquota   1        1

```

Remount

```bash
sudo mount -o remount /home
```

Create `aquota.user` and `aquota.group` file

```
sudo quotacheck -cum /home
cd /home
sudo quotacheck -avugfm
```

Load config

```
sudo quotaoff -a # shutdown all quota services
sudo quotaon -avug # start quota and load all config file
```

### Limiting one user home folder space

Setting up User disk limit

```bash
sudo edquota -u User

# Edit blocks it will automatic calculate inodes part

# Unit `KB` 0 is no limit

#    Disk quotas for user User (uid 1001):
#      Filesystem                   blocks       soft       hard     inodes     soft     hard
#      /dev/sda2                      1024       1000       1024          3        0        0
```

### Setting soft limit time

```bash
sudo edquota -t

#    Grace period before enforcing soft limits for users:
#    Time units may be: days, hours, minutes, or seconds
#      Filesystem             Block grace period     Inode grace period
#      /dev/sda2                     7days                  7days
```

### Get quota reports

```bash
sudo repquota -au

#    *** Report for user quotas on device /dev/sda2
#    Block grace time: 7days; Inode grace time: 7days
#                            Block limits                File limits
#    User            used    soft    hard  grace    used  soft  hard  grace
#    ----------------------------------------------------------------------
#    root      --      20       0       0              2     0     0
#    wilicw    --  301532       0       0           3378     0     0
#    User      +-    1024    1000    1024  6days       3     0     0
```

## Systemd

### Create a new Daemon

Create a shell script in any folder

Create and edit `/etc/systemd/system/service-name.service`

```conf
[Unit]
Description=Service desc

[Service]
ExecStart=/root/your-script.sh
Restart=always

[Install]
WantedBy=default.target
```

Enable the service

```bash
sudo systemctl enable service-name
```

---

# Server

## SSH Server

```bash
sudo apt install openssh-server # Install ssh
sudo systemctl enable ssh
sudo systemctl start ssh
```

config file in `/etc/ssh/sshd_config`

```
PermitRootLogin no # Disable root login

AllowUsers user1 user2 # Only allow user1 and user2 login

PasswordAuthentication yes # Use password login

Port 22 # Use 22 port

MaxAuthtries 10 # Max 10 times login try

Match User test3
    Banner /etc/Bannertest3 # Only user test3 show banner 
```

### Fail to ban

```bash
sudo apt install fail2ban
```

Edit /etc/fail2ban/jail.local

```bash
[sshd]
    enabled = true 
    port = ssh
    filter = sshd
    maxretry = 3
    findtime = 600 
    bantime = 600
```

```bash
sudo systemctl restart fail2ban 
```

## NAT Server (Network Address Translation)

Enable ip forward setting

```bash
sudo sysctl net.ipv4.ip_forward=1
```

See [IPtables -> NAT](#NAT)

## DHCP Server

```bash
sudo apt install isc-dhcp-server # Install DHCP
```

Add interface name in `/etc/default/isc-dhcp-server`

```
INTERFACES="eth0"
```

Edit `/etc/dhcp/dhcpd.conf`

```bash
    default-lease-time 600;
    max-lease-time 7200;
	
    subnet 192.168.0.0 netmask 255.255.255.0 {
        range 192.168.0.100 192.168.0.200;
        option subnet-mask 255.255.255.0;
        option domain-name-servers 8.8.8.8, 1.1.1.1;
        option routers 192.168.1.1;
    }
    # IP range 192.168.0.100-200
    # Netmask 255.255.255.0
    # Nameserver 8.8.8.8 1.1.1.1
    # Default gateway 192.168.1.1
```

### Assign IP

```bash
    host android {
        hardware ethernet 08:00:27:11:EB:C2; # MAC Address
        fixed-address 192.168.100.30; # Static IP
    }
```

Restart dhcp server

```bash
sudo /etc/init.d/isc-dhcp-server restart
```

Show dhcp client

```
cat /var/lib/dhcp/dhcpd.leases
```

## DNS Server

```bash
sudo apt install bind9 dnsutils # Install dns server and test tools
```

Zone: `skills39.co`

Edit `/etc/bind/named.conf.loacl`

```
zone "skills39.co" IN {
    type master;
    file "/etc/bind/skills39.co.db";
    allow-update {
        none;
    };
};
```

And edit `/etc/bind/skills39.co.db`

```
$TTL 60
@    IN    SOA    ns.skills39.co. root.skills39.co. (
    20
    60
    86400
    86400
    60
)
; Name Server
        IN    NS    ns.skills39.co
ns      IN    A     10.0.13.212

; A Record
@       IN    A    10.0.13.244
www     IN    A    10.0.13.244
```

Restart DNS server

```bash
sudo systemctl restart bind9
```

Test DNS server

```bash
dig skills39.cc
```

Output

```
; <<>> DiG 9.10.3-P4-Debian <<>> skills39.co
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 114
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
skills39.co.                      IN      A
;; ANSWER SECTION:
skills39.co.              60      IN      A       10.0.13.212
;; AUTHORITY SECTION:
skills39.co.              60      IN      NS      ns.skills39.co.
;; ADDITIONAL SECTION:
ns.skills39.co.           60      IN      A       10.0.13.212
;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Apr 12 12:27:43 CST 2019
;; MSG SIZE  rcvd: 88                              
```

## IPtables

### Overview

![IPtables Overview][iptablesimg]

### Allow lookback

```bash
sudo iptables -A INPUT -i lo -j ACCEPT
```

```bash
sudo iptables -A OUTPUT -i lo -j ACCEPT
```

### Block IP

```bash
sudo iptables -A INPUT -s [ip]/[CIDR] -j DROP
```

### NAT

Clean up the old setting

```bash
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X
```

NAT configuration via iptables

```bash
sudo iptables -A INPUT -i lo -j ACCEPT
# Allow loopback
sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
# Forward packages to ens33
```

### Port Forwarding

IN interface: `ens33`

```bash
sudo iptables -t nat -A PREROUTING -p tcp -i ens33 --dport 80 -j DNAT --to 192.168.1.20:80
sudo iptables -A FORWARD -p tcp --dport 80 -d 192.168.1.20 -j ACCEPT
# Forward tcp/80 to 192.168.1.20:80
```

## Samba Server

```bash
sudo apt install samba # Install samba server
```

Edit `/etc/samba/smb.conf`

```bash
[global]
    log file = /var/log/samba/log.%m
[file]
    comment = File share
    path = /home/file
    read only = yes
    public = yes
[user]
    comment = User home file
    path = /home/user
    read only = no
    writable = yes
    public = yes
```

Add samba user

```bash
sudo smdpasswd -a user  # User should exist in system
```

## FTP Server

```bash
sudo apt install vsftpd # Install vsftpd (ftp server)
```

Add `/etc/vsftpd.conf`

```bash
# Enable write access
write_enable=YES
```

### Users

Add `/etc/vsftpd.conf`

```bash
userlist_file=/etc/vsftpd.userlist
userlist_enable=YES
```

Create `/etc/vsftpd.userlist`

Only `User1` `User2` `User3` can access ftp server

```bash
User1
User2
User3
```

### Anonymous

Create `/var/ftp` and allow all user read

```bash
mkdir /var/ftp # Create ftp
chmod 555 /var/ftp # Read only
chown ftp.ftp /var/ftp/ # Change group to ftp
```

Edit `/etc/vsftpd.conf`

```bash
anon_root=/var/ftp
anonymous_enable=YES
no_anon_password=YES

# Enable anonymous writing permission
anon_upload_enable=YES
anon_other_write_enable=YES
anon_mkdir_write_enable=YES
```

Edit `/etc/vsftpd.userlist`

```bash
anonymous
```

### Configuration

Banner

```
banner_file=/var/ftp/bannerFile.txt
```

Restart vsftpd service

```bash
sudo systemctl restart vsftpd
```

## NTP Server

```bash
sudo apt install ntp # Install ntp
```

Edit `/etc/ntp.conf`

```bash
# NTP server in stdtime.gov.tw
pool tock.stdtime.gov.tw iburst
pool watch.stdtime.gov.tw iburst
pool time.stdtime.gov.tw iburst
pool clock.stdtime.gov.tw iburst
pool tick.stdtime.gov.tw iburst

# allow 10.0.0.0/8 use this ntp server
restrict 10.0.0.0 mask 255.0.0.0
```

Restart ntp server

```bash
sudo systemctl restart ntp
```

---

# Commands

## find

`-name` file name you want to find
`-regex` use Regex to find with name
`-exec` trigger a command when target meet the criteria
`-empty` find empty file

Common use

```bash
find . -name "a.txt" -exec rm {} \; #find file named 'a.txt' and delete it 
```

## tar

`c` add file in tar file (no compress)
`x` decompress or unpack a file from tar
`t` show file in tar
`z` use `gzip` (with compress)
`f name.tgz` output a file named `name.tgz`

Common use

```bash
tar -czvf file.tgz file/
```

---

# Others

## Run Level

0 shutdown

1 single user (no network)

2 multiple user (no network)

3 multiple user with network

4 ?

5 multiple user with gui

6 Reboot

Change run level to X

```bash
sudo init X
```

edit `/etc/inittab` to change default run level

Show run level

```bash
sudo runlevel
```

## CA on Nginx

Install openssl package

```bash
sudo apt install openssl
```

Generate a private key

```bash
openssl genrsa -out server.key 2048
```

Create a request file. The .csr file is request file

```bash
openssl req -new -key server.key -out server.csr
```

Common Name is your domain name

```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

Use Windows Server AD CS to auth this request file and get a public key

Rename the public key

```bash
mv certnew.crt server.pem
```

Edit nginx config file

```
sudo vim /etc/nginx/sies-avaliable/default
```
Add ssl configuration

```
ssl on;
ssl_certificate /[path]/server.pem;
ssl_certificate_key /[path]/server.key;
```

Restart nginx services

```
sudo systemctl restart nginx
```

## CA on Apache

```bash
sudo apt install openssl

openssl genrsa -out private.key 2048

openssl req -new -key private.key -out public.csr
```

Copy `public.csr` and rename to `public.crt`

```bash
mv public.csr public.crt
```

Move `public.crt` to `/etc/ssl/certs`

```bash
cp public.scr /etc/ssl/certs/
```

Move `private.key` `/etc/ssl/private`

```bash
cp private.key /etc/ssl/private/
```

Modify `/etc/apache2/site-available/ssl.conf`

```bash
SSLCertificateFile /etc/ssl/certs/public.crt
SSLCertificateKeyFile /etc/ssl/private/private.key
SSLCACertificatePath /etc/ssl/certs/
SSLCACertificateFile /etc/ssl/certs/[Intermediate Certificate].crt  #If using a self-signed certificate, omit this line
```

## Building Linux Kernel

- Use root to do following step

### Initialization

Download source code

```bash
cd ~
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.2.2.tar.xz # get kernel source code
mkdir /usr/src/kernel
tar xvf linux-5.2.2.tar.xz
mv linux-5.2.2 /usr/src/kernel
```

Install tools

```bash
apt install flex libffi-dev build-essential libncurses5-dev libssl-dev ccache gcc make
```

### Compile

```
cd /usr/src/kernel/linux-5.2.2
make mrproper
make clean
make menuconfig
make all
# Wait for 2 hours
```

### Install kernel

```
make modules_install
make install
grub-mkconfig -o /boot/grub/grub.cfg
reboot
```

---

# Documents

### SSH

- [sshd_config](https://linux.die.net/man/5/sshd_config)

### FTP

- [vsftp](https://linux.die.net/man/5/vsftpd.conf)

[logo]: https://www.debian.org/logos/openlogo.svg
[iptablesimg]: https://i.imgur.com/RO0lPSf.gif
