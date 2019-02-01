# Bash script to automate optimized WordOps setup

[![Build Status](https://travis-ci.com/VirtuBox/wo-nginx-setup.svg?branch=master)](https://travis-ci.com/VirtuBox/wo-nginx-setup) ![wo-nginx-setup](https://img.shields.io/github/license/VirtuBox/wo-nginx-setup.svg?style=flat) ![](https://img.shields.io/github/last-commit/virtubox/wo-nginx-setup.svg?style=flat)

* * *

## Server Stack

- Nginx 1.15.x/1.14 with [nginx-ee](https://virtubox.github.io/nginx-ee/)
- PHP-FPM 7.0/7.1/7.2/7.3
- MariaDB 10.1/10.2/10.3
- REDIS 5.0
- Fail2ban
- UFW Firewall
- ClamAV Antivirus
- Netdata
- Proftpd
- Acme.sh with [ee-acme-sh](https://virtubox.github.io/ee-acme-sh/)

* * *

**Documentation available here : [Ubuntu-Nginx-Web-Server](https://virtubox.github.io/ubuntu-nginx-web-server/)**

### Features

- Automated MariaDB server or client installation (10.1/10.2/10.3)
- Linux server tweaks
- [WordOps](https://github.com/WordOps/WordOps) automated installation
- php7.2-fpm installation & configuration
- Latest Nginx release compilation with [nginx-ee](https://virtubox.github.io/nginx-ee/)
- UFW configuration with custom SSH port
- Fail2ban Installation & Configuration
- Cloudflare visitor real IP configuration
- [Netdata](https://github.com/firehol/netdata/) and [EasyEngine-Dashboard](https://virtubox.github.io/easyengine-dashboard/) installation
- Proftpd installation & configuration

### Compatibility

- Ubuntu 16.04 LTS
- Ubuntu 18.04 LTS

### Requirements

- login as root
- ssh connection with ssh keys (Recommended SSH software on Windows : [Mobaxterm](https://mobaxterm.mobatek.net/))
- VPS or dedicated server with at least 2GB RAM (Recommended Proviers : Hetzner, OVH, DigitalOcean, Linode, Vultr, Scaleway)

### Usage

Download wo-nginx-setup

```bash
wget -O wo-nginx-setup.sh https://raw.githubusercontent.com/VirtuBox/wo-nginx-setup/master/wo-nginx-setup.sh
chmod +x wo-nginx-setup.sh
```

Launch interactive setup

```bash
./wo-nginx-setup.sh -i
```

**Non-interactive setup examples will be available soon**

Published & maintained by [VirtuBox](https://virtubox.net)
