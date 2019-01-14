#!/bin/bash
# -------------------------------------------------------------------------
#  WO-NGINX-SETUP - automated WordOps server setup script
# -------------------------------------------------------------------------
# Website:       https://virtubox.net
# GitHub:        https://github.com/VirtuBox/ee-nginx-setup
# Copyright (c) 2018 VirtuBox <contact@virtubox.net>
# This script is licensed under M.I.T
# -------------------------------------------------------------------------
# Version 0.1 - 2019-01-14
# -------------------------------------------------------------------------

CSI='\033['
CEND="${CSI}0m"
CGREEN="${CSI}1;32m"

##################################
# Variables
##################################

EXTPLORER_VER="2.1.10"

##################################
# Check if user is root
##################################

[ "$(id -u)" != "0" ] && {
    echo "Error: You must be root to run this script, please use the root user to install the software."
    echo ""
    echo "Use 'sudo su - root' to login as root"
    exit 1
}

### Set Bins Path ###
RM=/bin/rm
CP=/bin/cp
TAR=/bin/tar
GZIP=/bin/gzip

clear

[ ! -x /usr/bin/sudo ] && {
    apt-get update
    apt-get install sudo
}



##################################
# help
##################################

_help() {
    echo "WO-NGINX-SETUP - automated WordOps server setup script"
    echo "Usage: ./wo-nginx-setup.sh [options]"
    echo "  Options:"
    echo "       --remote-mysql ..... install mysql-client for remote mysql access"
    echo "       -i | --interactive ..... interactive installation mode"
    echo "       --proftpd ..... install proftpd"
    echo "       --mariadb <mariadb version> ..... set mariadb version manually (default 10.3)"
    echo " Other options :"
    echo "       -h, --help, help ... displays this help information"
    echo ""
    return 0
}

##################################
# SSH Keys check
##################################

if [ -d $HOME/.ssh ]; then
    ecdsa_keys_check=$(grep "ecdsa-sha2" -r $HOME/.ssh)
    rsa_keys_check=$(grep "ssh-rsa" -r $HOME/.ssh)
    ed25519_keys_check=$(grep "ssh-ed25519" -r $HOME/.ssh)
    if [ -z "$ecdsa_keys_check" ] && [ -z "$rsa_keys_check" ] && [ -z "$ed25519_keys_check" ]; then
        echo "This script require to use ssh keys authentification. Please make sure you have properly added your public ssh keys into .ssh/authorized_keys"
        exit 1
    fi
else
    echo "This script require to use ssh keys authentification. Please make sure you have properly added your public ssh keys into .ssh/authorized_keys"
    exit 1
fi

##################################
# Arguments Parsing
##################################

### Read config
if [ "${#}" = "0" ] && [ -f "config.inc" ]; then
    . ./config.inc
else
    while [ "${#}" -gt 0 ]; do
        case "${1}" in
            -i | --interactive)
                INTERACTIVE_SETUP="y"
            ;;
            --proftpd)
                PROFTPD_INSTALL="y"
            ;;
            --remote-mysql)
                MARIADB_CLIENT_INSTALL="y"
            ;;
            --mariadb)
                MARIADB_VERSION_INSTALL="$2"
                shift
            ;;
            --secure-backend)
                SECURE_22222="y"
            ;;
            --clamav)
                CLAMAV_INSTALL="y"
            ;;
            --ee-cleanup)
                EE_CLEANUP="y"
            ;;
            -h|--help)
                _help
                exit 1
            ;;
            *) ;;
        esac
        shift
    done
fi

##################################
# Welcome
##################################

echo ""
echo "Welcome to Wo-Nginx-setup script."
echo ""

if [ -d /etc/ee ]; then
    EE_PREVIOUS_INSTALL=1
fi

if  [ -d /etc/wo ]; then
    WO_PREVIOUS_INSTALL=1
fi

##################################
# Menu
##################################

if [ "$MARIADB_CLIENT_INSTALL" = "y" ]; then
    echo ""
    echo "What is the IP of your remote database ?"
    read -p "IP : " MARIADB_REMOTE_IP
    echo ""
    echo "What is the user of your remote database ?"
    read -p "User : " MARIADB_REMOTE_USER
    echo ""
    echo "What is the password of your remote database ?"
    read -s -p "password [hidden] : " MARIADB_REMOTE_PASSWORD
fi


if [ "$INTERACTIVE_SETUP" = "y" ]; then
    if [ ! -d /etc/mysql ]; then
        echo "#####################################"
        echo "MariaDB server"
        echo "#####################################"
        echo ""
        echo "Do you want to install MariaDB-server ? (y/n)"
        while [[ $MARIADB_SERVER_INSTALL != "y" && $MARIADB_SERVER_INSTALL != "n" ]]; do
            read -p "Select an option [y/n]: " MARIADB_SERVER_INSTALL
        done
        if [ "$MARIADB_SERVER_INSTALL" = "n" ]; then
            echo ""
            echo "Do you want to install MariaDB-client for a remote database ? (y/n)"
            while [[ $MARIADB_CLIENT_INSTALL != "y" && $MARIADB_CLIENT_INSTALL != "n" ]]; do
                read -p "Select an option [y/n]: " MARIADB_CLIENT_INSTALL
            done
        fi
        if [ "$MARIADB_CLIENT_INSTALL" = "y" ]; then
            echo ""
            echo "What is the IP of your remote database ?"
            read -p "IP : " MARIADB_REMOTE_IP
            echo ""
            echo "What is the user of your remote database ?"
            read -p "User : " MARIADB_REMOTE_USER
            echo ""
            echo "What is the password of your remote database ?"
            read -s -p "password [hidden] : " MARIADB_REMOTE_PASSWORD
        fi
        if [[ "$MARIADB_SERVER_INSTALL" == "y" || "$MARIADB_CLIENT_INSTALL" == "y" ]]; then
            echo ""
            echo "What version of MariaDB Client/Server do you want to install, 10.1, 10.2 or 10.3 ?"
            while [[ $MARIADB_VERSION_INSTALL != "10.1" && $MARIADB_VERSION_INSTALL != "10.2" && $MARIADB_VERSION_INSTALL != "10.3" ]]; do
                read -p "Select an option [10.1 / 10.2 / 10.3]: " MARIADB_VERSION_INSTALL
            done
        fi
        sleep 1
    fi
    if [ ! -d /etc/nginx ]; then
        echo ""
        echo "#####################################"
        echo "Nginx"
        echo "#####################################"
        echo ""
        echo "Do you want to compile the latest Nginx Mainline [1] or Stable [2] Release ?"
        while [[ $NGINX_RELEASE != "1" && $NGINX_RELEASE != "2" ]]; do
            read -p "Select an option [1-2]: " NGINX_RELEASE
        done
        echo ""
        echo "Do you want Ngx_Pagespeed ? (y/n)"
        while [[ $PAGESPEED != "y" && $PAGESPEED != "n" ]]; do
            read -p "Select an option [y/n]: " PAGESPEED
        done
        echo ""
        echo "Do you want NAXSI WAF (still experimental)? (y/n)"
        while [[ $NAXSI != "y" && $NAXSI != "n" ]]; do
            read -p "Select an option [y/n]: " NAXSI
        done
        echo ""
        echo "Do you want RTMP streaming module ?"
        while [[ $RTMP != "y" && $RTMP != "n" ]]; do
            read -p "Select an option [y/n]: " RTMP
        done
    fi
    sleep 1
    echo ""
    if [ ! -d /etc/proftpd ]; then
        echo ""
        echo "#####################################"
        echo "FTP"
        echo "#####################################"
        echo "Do you want proftpd ? (y/n)"
        while [[ $PROFTPD_INSTALL != "y" && $PROFTPD_INSTALL != "n" ]]; do
            read -p "Select an option [y/n]: " PROFTPD_INSTALL
        done
    fi
    echo ""
    echo "#####################################"
    echo "Starting server setup in 5 seconds"
    echo "use CTRL + C if you want to cancel installation"
    echo "#####################################"
    sleep 5
fi

##################################
# Update packages
##################################

echo "##########################################"
echo " Updating Packages"
echo "##########################################"

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get autoremove -y --purge
sudo apt-get autoclean -y

echo "##########################################"
echo " Updating Packages   [OK]"
echo "##########################################"

##################################
# Useful packages
##################################

echo "##########################################"
echo " Installing useful packages"
echo "##########################################"

sudo apt-get install haveged curl git unzip zip fail2ban htop nload nmon tar gzip ntp gnupg gnupg2 wget pigz tree ccze mycli -y

# ntp time
sudo systemctl enable ntp

# increase history size
export HISTSIZE=10000

echo "##########################################"
echo " Checking required executable path"
echo "##########################################"

### Make Sure Bins Exists ###
verify_bins() {
    [ ! -x $GZIP ] && {
        echo "Executable $GZIP does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $TAR ] && {
        echo "Executable $TAR does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $RM ] && {
        echo "File $RM does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $CP ] && {
        echo "File $CP does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $MKDIR ] && {
        echo "File $MKDIR does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $GREP ] && {
        echo "File $GREP does not exists. Make sure correct path is set in $0."
        exit 0
    }
    [ ! -x $FIND ] && {
        echo "File $GREP does not exists. Make sure correct path is set in $0."
        exit 0
    }
}

verify_bins

##################################
# clone repository
##################################
echo "###########################################"
echo " Cloning Ubuntu-nginx-web-server repository"
echo "###########################################"

if [ ! -d $HOME/ubuntu-nginx-web-server ]; then
    git clone https://github.com/VirtuBox/ubuntu-nginx-web-server.git $HOME/ubuntu-nginx-web-server
else
    git -C $HOME/ubuntu-nginx-web-server pull origin master
fi

##################################
# Secure SSH server
##################################

# get current ssh port
CURRENT_SSH_PORT=$(grep "Port" /etc/ssh/sshd_config | awk -F " " '{print $2}')

# download secure sshd_config
sudo cp -f $HOME/ubuntu-nginx-web-server/etc/ssh/sshd_config /etc/ssh/sshd_config

# change ssh default port
sudo sed -i "s/Port 22/Port $CURRENT_SSH_PORT/" /etc/ssh/sshd_config

# restart ssh service
sudo service ssh restart

##################################
# ufw
##################################

echo "##########################################"
echo " Configuring ufw"
echo "##########################################"

if [ ! -d /etc/ufw ]; then
    sudo apt-get install ufw -y
fi

# define firewall rules

sudo ufw logging low
sudo ufw default allow outgoing
sudo ufw default deny incoming

# default ssh port
sudo ufw allow 22

# custom ssh port
if [ "$CURRENT_SSH_PORT" != "22" ];then
    sudo ufw allow "$CURRENT_SSH_PORT"
fi

# dns
sudo ufw allow 53

# nginx
sudo ufw allow http
sudo ufw allow https

# ntp
sudo ufw allow 123

# dhcp client
sudo ufw allow 68

# dhcp ipv6 client
sudo ufw allow 546

# rsync
sudo ufw allow 873

# easyengine backend
sudo ufw allow 22222

# optional for monitoring

# SNMP UDP port
#sudo ufw allow 161

# Netdata web interface
#sudo ufw allow 1999

# Librenms linux agent
#sudo ufw allow 6556

# Zabbix-agent
#sudo ufw allow 10050

##################################
# Sysctl tweaks +  open_files limits
##################################

echo "##########################################"
echo " Applying Linux Kernel tweaks"
echo "##########################################"

sudo cp -f $HOME/ubuntu-nginx-web-server/etc/sysctl.d/60-ubuntu-nginx-web-server.conf /etc/sysctl.d/60-ubuntu-nginx-web-server.conf
sudo sysctl -e -p /etc/sysctl.d/60-ubuntu-nginx-web-server.conf
sudo cp -f $HOME/ubuntu-nginx-web-server/etc/security/limits.conf /etc/security/limits.conf

# Redis transparent_hugepage
echo never >/sys/kernel/mm/transparent_hugepage/enabled

# disable ip forwarding if docker is not installed
if [ ! -x /usr/bin/docker ]; then

    echo "" >>/etc/sysctl.d/60-ubuntu-nginx-web-server.conf
    {
        echo "# Disables packet forwarding"
        echo "net.ipv4.ip_forward = 0"
        echo "net.ipv4.conf.all.forwarding = 0"
        echo "net.ipv4.conf.default.forwarding = 0"
        echo "net.ipv6.conf.all.forwarding = 0"
        echo "net.ipv6.conf.default.forwarding = 0"
    } >>/etc/sysctl.d/60-ubuntu-nginx-web-server.conf

fi

# additional systcl configuration with network interface name
# get network interface names like eth0, ens18 or eno1
# for each interface found, add the following configuration to sysctl

NET_INTERFACES_WAN=$(ip -4 route get 8.8.8.8 | grep -oP "dev [^[:space:]]+ " | cut -d ' ' -f 2)
echo "" >>/etc/sysctl.d/60-ubuntu-nginx-web-server.conf
{
    echo "# do not autoconfigure IPv6 on $NET_INTERFACES_WAN"
    echo "net.ipv6.conf.$NET_INTERFACES_WAN.autoconf = 0"
    echo "net.ipv6.conf.$NET_INTERFACES_WAN.accept_ra = 0"
    echo "net.ipv6.conf.$NET_INTERFACES_WAN.accept_ra = 0"
    echo "net.ipv6.conf.$NET_INTERFACES_WAN.autoconf = 0"
    echo "net.ipv6.conf.$NET_INTERFACES_WAN.accept_ra_defrtr = 0"
} >>/etc/sysctl.d/60-ubuntu-nginx-web-server.conf


##################################
# Add MariaDB 10.3 repository
##################################

if [ -z "$MARIADB_SERVER_INSTALL" ] || [ "$MARIADB_SERVER_INSTALL" = "y" ]; then
    [ -z "$MARIADB_VERSION_INSTALL" ] && {
        MARIADB_VERSION_INSTALL="10.3"
    }
    if [ ! -f /etc/apt/sources.list.d/mariadb.list ]; then
        echo ""
        echo "##########################################"
        echo " Adding MariaDB $MARIADB_VERSION_INSTALL repository"
        echo "##########################################"

        wget -O mariadb_repo_setup https://downloads.mariadb.com/MariaDB/mariadb_repo_setup
        chmod +x mariadb_repo_setup
        ./mariadb_repo_setup --mariadb-server-version="$MARIADB_VERSION_INSTALL" --skip-maxscale -y
        rm mariadb_repo_setup
        sudo apt-get update

    fi

    ##################################
    # MariaDB 10.3 install
    ##################################

    # install mariadb server non-interactive way
    if [ ! -d /etc/mysql ]; then
        echo ""
        echo "##########################################"
        echo " Installing MariaDB server $MARIADB_VERSION_INSTALL"
        echo "##########################################"

        # generate random password
        MYSQL_ROOT_PASS="$(date +%s | sha256sum | base64 | head -c 32)"
        export DEBIAN_FRONTEND=noninteractive                             # to avoid prompt during installation
        sudo debconf-set-selections <<<"mariadb-server-${MARIADB_VERSION_INSTALL} mysql-server/root_password password ${MYSQL_ROOT_PASS}"
        sudo debconf-set-selections <<<"mariadb-server-${MARIADB_VERSION_INSTALL} mysql-server/root_password_again password ${MYSQL_ROOT_PASS}"
        # install mariadb server
        DEBIAN_FRONTEND=noninteractive apt-get install -qq mariadb-server # -qq implies -y --force-yes
        # save credentials in .my.cnf and copy it in /etc/mysql/conf.d for easyengine
        echo -e '[client]\nuser = root' > $HOME/.my.cnf
        echo "password = $MYSQL_ROOT_PASS" >>$HOME/.my.cnf
        cp -f $HOME/.my.cnf /etc/mysql/conf.d/my.cnf

        ## mysql_secure_installation non-interactive way
        mysql -e "GRANT ALL PRIVILEGES on *.* to 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASS' WITH GRANT OPTION;"
        # remove anonymous users
        mysql -e "DROP USER ''@'localhost'" > /dev/null 2>&1
        mysql -e "DROP USER ''@'$(hostname)'" > /dev/null 2>&1
        # remove test database
        mysql -e "DROP DATABASE test" > /dev/null 2>&1
        # flush privileges
        mysql -e "FLUSH PRIVILEGES"


        ##################################
        # MariaDB tweaks
        ##################################

        echo "##########################################"
        echo " Optimizing MariaDB configuration"
        echo "##########################################"

        cp -f $HOME/ubuntu-nginx-web-server/etc/mysql/my.cnf /etc/mysql/my.cnf

        # AVAILABLE_MEMORY=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        # PERCENT="40"
        # MYSQL_MEMORY_USAGE=$((MEM*PERCENT/100))

        # sed -i -e "/\[mysqld\]/,/\[.*\]/s/^innodb_buffer_pool_size/#innodb_buffer_pool_size/" /etc/mysql/my.cnf

        # sed -i -e 's/innodb_buffer_pool_size = [0-9]\+M/innodb_buffer_pool_size = 512M/' /etc/mysql/my.cnf

        # AVAILABLE_MEMORY=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        # BUFFER_POOL_SIZE=$(( $AVAILABLE_MEMORY / 2000 ))
        # LOG_FILE_SIZE=$(( $AVAILABLE_MEMORY / 16000 ))
        # LOG_BUFFER_SIZE=$(( $AVAILABLE_MEMORY / 8000 ))

        # sudo sed -i "s/innodb_buffer_pool_size = 2G/innodb_buffer_pool_size = $BUFFER_POOL_SIZE\\M/" /etc/mysql/my.cnf
        # sudo sed -i "s/innodb_log_file_size    = 256M/innodb_log_file_size    = $LOG_FILE_SIZE\\M/" /etc/mysql/my.cnf
        # sudo sed -i "s/innodb_log_buffer_size  = 512M/innodb_log_buffer_size  = $LOG_BUFFER_SIZE\\M/" /etc/mysql/my.cnf

        # stop mysql service to apply new InnoDB log file size
        sudo service mysql stop

        # mv previous log file
        sudo mv /var/lib/mysql/ib_logfile0 /var/lib/mysql/ib_logfile0.bak
        sudo mv /var/lib/mysql/ib_logfile1 /var/lib/mysql/ib_logfile1.bak

        # increase mariadb open_files_limit
        cp -f $HOME/ubuntu-nginx-web-server/etc/systemd/system/mariadb.service.d/limits.conf /etc/systemd/system/mariadb.service.d/limits.conf

        # reload daemon
        systemctl daemon-reload

        # restart mysql
        service mysql start

    fi
fi

if [ "$MARIADB_CLIENT_INSTALL" = "y" ]; then

    echo "installing mariadb-client"

    # install mariadb-client
    apt-get install -y mariadb-client

    # set mysql credentials in .my.cnf
    echo "[client]" >>$HOME/.my.cnf
    echo "host = $MARIADB_REMOTE_IP" >>$HOME/.my.cnf
    echo "port = 3306" >>$HOME/.my.cnf
    echo "user = $MARIADB_REMOTE_USER" >>$HOME/.my.cnf
    echo "password = $MARIADB_REMOTE_PASSWORD" >>$HOME/.my.cnf

    # copy .my.cnf in /etc/mysql/conf.d/ for easyengine
    cp $HOME/.my.cnf /etc/mysql/conf.d/my.cnf
fi

##################################
# EasyEngine automated install
##################################

if [ -z "$WO_PREVIOUS_INSTALL" ]; then

    if [ ! -f $HOME/.gitconfig ]; then
        # define git username and email for non-interactive install
        sudo bash -c 'echo -e "[user]\n\tname = $USER\n\temail = $USER@$HOSTNAME" > $HOME/.gitconfig'
    fi
    if [ ! -x /usr/local/bin/wo ]; then
        echo "##########################################"
        echo " Installing EasyEngine"
        echo "##########################################"

        wget -O wo https://raw.githubusercontent.com/WordOps/WordOps/master/install
        chmod +x wo
        ./wo
        source /etc/bash_completion.d/wo_auto.rc
        rm wo

    fi

    ##################################
    # WordOps stacks install
    ##################################

    if [ "$MARIADB_CLIENT_INSTALL" = "y" ]; then
        # change MySQL host to % in case of remote MySQL server
        sudo sed -i 's/grant-host = localhost/grant-host = \%/' /etc/wo/wo.conf
    fi

    echo "##########################################"
    echo " Installing WordOps Stack"
    echo "##########################################"

    if [ -d /etc/mysql ]; then
        # install nginx, php, postfix, memcached
        wo stack install
        # install php7, redis, easyengine backend & phpredisadmin
        wo stack install --redis --admin --phpredisadmin
    else
        wo stack install --nginx --php --redis --wpcli
    fi

    ##################################
    # Fix phpmyadmin install
    ##################################
    echo "##########################################"
    echo " Updating phpmyadmin"
    echo "##########################################"

    # install composer
    cd ~/ || exit
    curl -sS https://getcomposer.org/installer | php
    mv composer.phar /usr/bin/composer

    # change owner of /var/www to allow composer cache
    chown www-data:www-data /var/www
    # update phpmyadmin with composer
    if [ -d /var/www/22222/htdocs/db/pma ]; then
        sudo -u www-data -H composer update -d /var/www/22222/htdocs/db/pma/
    fi

    ##################################
    # Allow www-data shell access for SFTP + add .bashrc settings et completion
    ##################################
    echo "##########################################"
    echo " Configuring www-data shell access"
    echo "##########################################"

    # change www-data shell
    usermod -s /bin/bash www-data

    if [ ! -f /etc/bash_completion.d/wp-completion.bash ]; then
        # download wp-cli bash-completion
        sudo wget -qO /etc/bash_completion.d/wp-completion.bash https://raw.githubusercontent.com/wp-cli/wp-cli/master/utils/wp-completion.bash
    fi
    if [ ! -f /var/www/.profile ] && [ ! -f /var/www/.bashrc ]; then
        # create .profile & .bashrc for www-data user
        cp -f $HOME/ubuntu-nginx-web-server/var/www/.profile /var/www/.profile
        cp -f $HOME/ubuntu-nginx-web-server/var/www/.bashrc /var/www/.bashrc

        # set www-data as owner
        sudo chown www-data:www-data /var/www/.profile
        sudo chown www-data:www-data /var/www/.bashrc
    fi

    # install nanorc for www-data
    sudo -u www-data -H curl https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh | sh
fi

##################################
# Install php7.2-fpm
##################################

echo "##########################################"
echo " Installing php7.2-fpm"
echo "##########################################"

sudo apt-get install php7.2-fpm php7.2-xml php7.2-bz2 php7.2-zip php7.2-mysql php7.2-intl php7.2-gd \
php7.2-curl php7.2-soap php7.2-mbstring php7.2-xsl php7.2-bcmath -y

# copy php7.2 config files
sudo cp -rf $HOME/ubuntu-nginx-web-server/etc/php/7.2/* /etc/php/7.2/
sudo service php7.2-fpm restart

# commit changes
git -C /etc/php/ add /etc/php/ && git -C /etc/php/ commit -m "add php7.2 configuration"


##################################
# Compile latest nginx release from source
##################################

# set nginx-ee arguments

if [ -z "$NGINX_RELEASE" ]; then
    NGINX_BUILD_VER='--mainline'
else
    NGINX_BUILD_VER='--stable'
fi

if [ $PAGESPEED = "y" ]; then
    BUILD_PAGESPEED='--pagespeed'
else
    BUILD_PAGESPEED=''
fi

if [ $NAXSI = "y" ]; then
    BUILD_NAXSI='--naxsi'
else
    BUILD_NAXSI=''
fi

if [ $RTMP = "y" ]; then
    BUILD_RTMP='--rtmp'
else
    BUILD_RTMP=''
fi

echo "##########################################"
echo " Compiling Nginx with nginx-ee"
echo "##########################################"

wget -O nginx-build.sh https://virtubox.net/nginx-ee
chmod +x nginx-build.sh

./nginx-build.sh "$NGINX_BUILD_VER" "$BUILD_PAGESPEED" "$BUILD_NAXSI" "$BUILD_RTMP"

##################################
# Add nginx additional conf
##################################

echo "##########################################"
echo " Configuring Nginx"
echo "##########################################"

# php7.1 & 7.2 common configurations

cp -rf $HOME/ubuntu-nginx-web-server/etc/nginx/common/* /etc/nginx/common/

# commit changes
git -C /etc/nginx/ add /etc/nginx/ && git -C /etc/nginx/ commit -m "update common configurations"

# common nginx configurations

cp -rf $HOME/ubuntu-nginx-web-server/etc/nginx/conf.d/* /etc/nginx/conf.d/
cp -f $HOME/ubuntu-nginx-web-server/etc/nginx/proxy_params /etc/nginx/proxy_params
cp -f $HOME/ubuntu-nginx-web-server/etc/nginx/mime.types /etc/nginx/mime.types

# commit changes
git -C /etc/nginx/ add /etc/nginx/ && git -C /etc/nginx/ commit -m "update conf.d configurations"

# optimized nginx.config
cp -f $HOME/ubuntu-nginx-web-server/etc/nginx/nginx.conf /etc/nginx/nginx.conf

# reduce nginx logs rotation
sed -i 's/size 10M/weekly/' /etc/logrotate.d/nginx
sed -i 's/rotate 52/rotate 4/' /etc/logrotate.d/nginx

wget -O $HOME/nginx-cloudflare-real-ip.sh https://raw.githubusercontent.com/VirtuBox/nginx-cloudflare-real-ip/master/nginx-cloudflare-real-ip.sh
chmod +x $HOME/nginx-cloudflare-real-ip.sh
$HOME/nginx-cloudflare-real-ip.sh

# commit changes
git -C /etc/nginx/ add /etc/nginx/ && git -C /etc/nginx/ commit -m "update nginx.conf and setup cloudflare visitor real IP restore"

# check nginx configuration
CONF_22222=$(grep -c netdata /etc/nginx/sites-available/22222)
CONF_UPSTREAM=$(grep -c netdata /etc/nginx/conf.d/upstream.conf)

if [ "$CONF_22222" = "0" ]; then
    # add nginx reverse-proxy for netdata on https://yourserver.hostname:22222/netdata/
    sudo cp -f $HOME/ubuntu-nginx-web-server/etc/nginx/sites-available/22222 /etc/nginx/sites-available/22222
fi

if [ "$CONF_UPSTREAM" = "0" ]; then
    # add netdata, php7.1 and php7.2 upstream
    sudo cp -f $HOME/ubuntu-nginx-web-server/etc/nginx/conf.d/upstream.conf /etc/nginx/conf.d/upstream.conf
fi

VERIFY_NGINX_CONFIG=$(nginx -t 2>&1 | grep failed)
echo "##########################################"
echo "Checking Nginx configuration"
echo "##########################################"
if [ -z "$VERIFY_NGINX_CONFIG" ]; then
    echo "##########################################"
    echo "Reloading Nginx"
    echo "##########################################"
    sudo service nginx reload
else
    echo "##########################################"
    echo "Nginx configuration is not correct"
    echo "##########################################"
fi

##################################
# Add fail2ban configurations
##################################
echo "##########################################"
echo " Configuring Fail2Ban"
echo "##########################################"

cp -rf $HOME/ubuntu-nginx-web-server/etc/fail2ban/filter.d/* /etc/fail2ban/filter.d/
cp -rf $HOME/ubuntu-nginx-web-server/etc/fail2ban/jail.d/* /etc/fail2ban/jail.d/

fail2ban-client reload

if [ $CLAMAV_INSTALL = "y" ]; then

    ##################################
    # Install ClamAV
    ##################################
    echo "##########################################"
    echo " Installing ClamAV"
    echo "##########################################"

    if [ ! -x /usr/bin/clamscan ]; then
        apt-get install clamav -y
    fi

    ##################################
    # Update ClamAV database fail2ban configurations
    ##################################
    echo "##########################################"
    echo " Updating ClamAV signature database"
    echo "##########################################"

    /etc/init.d/clamav-freshclam stop
    freshclam
    /etc/init.d/clamav-freshclam start
fi

##################################
# Install cheat & nanorc
##################################
echo "##########################################"
echo " Installing cheat.sh & nanorc & mysqldump script"
echo "##########################################"

if [ ! -x /usr/bin/cht.sh ]; then
    curl -s https://cht.sh/:cht.sh >/usr/bin/cht.sh
    chmod +x /usr/bin/cht.sh

    cd || exit 1
    echo "alias cheat='cht.sh'" >>.bashrc
    source $HOME/.bashrc
fi

wget https://raw.githubusercontent.com/scopatz/nanorc/master/install.sh -qO- | sh

wget -qO mysqldump.sh https://github.com/VirtuBox/bash-scripts/blob/master/backup/mysqldump/mysqldump.sh
chmod +x mysqldump.sh

##################################
# Install ProFTPd
##################################

if [ "$PROFTPD_INSTALL" = "y" ]; then

    echo "##########################################"
    echo " Installing Proftpd"
    echo "##########################################"

    apt-get install proftpd -y

    # secure proftpd and enable PassivePorts

    sed -i 's/# DefaultRoot/DefaultRoot/' /etc/proftpd/proftpd.conf
    sed -i 's/# RequireValidShell/RequireValidShell/' /etc/proftpd/proftpd.conf
    sed -i 's/# PassivePorts                  49152 65534/PassivePorts                  49000 50000/' /etc/proftpd/proftpd.conf

    sudo service proftpd restart

    if [ -d /etc/ufw ]; then
        # ftp active port
        sudo ufw allow 21
        # ftp passive ports
        sudo ufw allow 49000:50000/tcp
    fi

    if [ -d /etc/fail2ban ]; then
        echo -e '\n[proftpd]\nenabled = true\n' >> /etc/fail2ban/jail.d/custom.conf
        fail2ban-client reload

    fi
fi
##################################
# Install Netdata
##################################

if [ ! -d /etc/netdata ]; then
    echo "##########################################"
    echo " Installing Netdata"
    echo "##########################################"

    ## optimize netdata resources usage
    echo 1 >/sys/kernel/mm/ksm/run
    echo 1000 >/sys/kernel/mm/ksm/sleep_millisecs

    ## install nedata
    wget -O kickstart.sh https://my-netdata.io/kickstart.sh
    chmod +x kickstart.sh
    ./kickstart.sh all --dont-wait >>/tmp/ubuntu-nginx-web-server.log 2>&1
    rm kickstart.sh

    if [ "$MARIADB_SERVER_INSTALL" = "y" ]; then
        mysql -e  "create user 'netdata'@'localhost';"
        mysql -e  "grant usage on *.* to 'netdata'@'localhost';"
        mysql -e  "flush privileges;"
        elif [ "$MARIADB_CLIENT_INSTALL" = "y" ]; then
        mysql -e  "create user 'netdata'@'%';"
        mysql -e  "grant usage on *.* to 'netdata'@'%';"
        mysql -e  "flush privileges;"
    fi

    ## disable email notifigrep -cions
    sudo sed -i 's/SEND_EMAIL="YES"/SEND_EMAIL="NO"/' /usr/lib/netdata/conf.d/health_alarm_notify.conf
    sudo service netdata restart

fi

##################################
# Install EasyEngine Dashboard
##################################

echo "##########################################"
echo " Installing EasyEngine Dashboard"
echo "##########################################"

if [ ! -d /var/www/22222/htdocs/files ]; then

    mkdir -p /var/www/22222/htdocs/files
    wget -qO /var/www/22222/htdocs/files/ex.zip http://extplorer.net/attachments/download/74/eXtplorer_$EXTPLORER_VER.zip
    cd /var/www/22222/htdocs/files || exit 1
    unzip ex.zip
    rm ex.zip
fi

cd /var/www/22222 || exit

## download latest version of EasyEngine-dashboard
cd /tmp || exit
git clone https://github.com/VirtuBox/easyengine-dashboard.git
cp -rf /tmp/easyengine-dashboard/* /var/www/22222/htdocs/
chown -R www-data:www-data /var/www/22222/htdocs

##################################
# Install Acme.sh
##################################

echo "##########################################"
echo " Installing Acme.sh"
echo "##########################################"

# install acme.sh if needed
echo ""
echo "checking if acme.sh is already installed"
echo ""
if [ ! -f $HOME/.acme.sh/acme.sh ]; then
    echo ""

    echo ""
    wget -O - https://get.acme.sh | sh
    cd || exit
    source $HOME/.bashrc
fi

##################################
# Install cheat.sh
##################################

if [ ! -x /usr/bin/cht.sh ]; then
    echo "##########################################"
    echo " Installing cheat.sh"
    echo "##########################################"

    curl https://cht.sh/:cht.sh > /usr/local/bin/cht.sh || wget -qO  /usr/local/bin/cht.sh https://cht.sh/:cht.sh
    chmod +x /usr/local/bin/cht.sh
    echo 'alias cheat="cht.sh"' >> $HOME/.bashrc

fi

##################################
# Secure WordOps Dashboard with Acme.sh
##################################

if [ "$SECURE_22222" = "y" ]; then

    MY_HOSTNAME=$(/bin/hostname -f)
    MY_IP=$(ip -4 address show ${NET_INTERFACES_WAN} | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
    MY_HOSTNAME_IP=$(/usr/bin/dig +short @8.8.8.8 "$MY_HOSTNAME")

    if [ "$MY_IP" = "$MY_HOSTNAME_IP" ]; then
        echo "##########################################"
        echo " Securing EasyEngine Backend"
        echo "##########################################"
        apt-get install -y socat


        if [ ! -d $HOME/.acme.sh/${MY_HOSTNAME}_ecc ]; then
            $HOME/.acme.sh/acme.sh --issue -d $MY_HOSTNAME -k ec-384 --standalone --pre-hook "service nginx stop" --post-hook "service nginx start"
        fi

        if [ -d /etc/letsencrypt/live/$MY_HOSTNAME ]; then
            rm -rf /etc/letsencrypt/live/$MY_HOSTNAME/*
        else
            mkdir -p /etc/letsencrypt/live/$MY_HOSTNAME
        fi

        # install the cert and reload nginx
        if [ -f $HOME/.acme.sh/${MY_HOSTNAME}_ecc/fullchain.cer ]; then
            $HOME/.acme.sh/acme.sh --install-cert -d ${MY_HOSTNAME} --ecc \
            --cert-file /etc/letsencrypt/live/${MY_HOSTNAME}/cert.pem \
            --key-file /etc/letsencrypt/live/${MY_HOSTNAME}/key.pem \
            --fullchain-file /etc/letsencrypt/live/${MY_HOSTNAME}/fullchain.pem \
            --reloadcmd "service nginx restart"
        fi

        if [ -f /etc/letsencrypt/live/${MY_HOSTNAME}/fullchain.pem ] && [ -f /etc/letsencrypt/live/${MY_HOSTNAME}/key.pem ]; then
            sed -i "s/ssl_certificate \\/var\\/www\\/22222\\/cert\\/22222.crt;/ssl_certificate \\/etc\\/letsencrypt\\/live\\/${MY_HOSTNAME}\\/fullchain.pem;/" /etc/nginx/sites-available/22222
            sed -i "s/ssl_certificate_key \\/var\\/www\\/22222\\/cert\\/22222.key;/ssl_certificate_key    \\/etc\\/letsencrypt\\/live\\/${MY_HOSTNAME}\\/key.pem;/" /etc/nginx/sites-available/22222
        fi
        service nginx reload

    fi
fi

##################################
# Cleanup previous EasyEngine install
##################################

if [ "$EE_CLEANUP" = "y" ]; then
    echo "##########################################"
    echo " Cleaning up EasyEngine"
    echo "##########################################"
    tar -I pigz -cvf $HOME/ee-backup.tar.gz /etc/ee /var/lib/ee /usr/lib/ee/templates

    rm -rf /etc/ee /var/lib/ee /usr/lib/ee
    rm -rf /usr/local/lib/python3.6/dist-packages/ee-3.*

    apt-get -y autoremove php5.6-fpm php5.6-common --purge
    apt-get -y autoremove php7.0-fpm php7.0-common --purge

fi