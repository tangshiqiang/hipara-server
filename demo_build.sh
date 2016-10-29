#!/bin/bash
# demo_build.sh -- builds and deploys files for HIPARA server
#	by Tin Tam <tin@hipara.org>
#
#

echo -e "
 _   _ ___ ____   _    ____      _      ____  _____ ______     _______ ____ 
| | | |_ _|  _ \ / \  |  _ \    / \    / ___|| ____|  _ \ \   / / ____|  _ \ 
| |_| || || |_) / _ \ | |_) |  / _ \   \___ \|  _| | |_) \ \ / /|  _| | |_) |
|  _  || ||  __/ ___ \|  _ <  / ___ \   ___) | |___|  _ < \ V / | |___|  _ < 
|_| |_|___|_| /_/   \_\_| \_\/_/   \_\ |____/|_____|_| \_\ \_/  |_____|_| \_\


#############################################################################
#
# Welcome to the HIPARA Server Installation
# 
# This script will build and move files to a self contained enviornment
# All files related to HIPARA Server can be found in /opt/hipara
#
# This scirpt is intended to peform a demo installation on Debian based
#  operating systems (Debian, Ubuntu, Mint, etc..)
#
# For other platforms and deployments, please visit:
# https://github.com/jbc22/hipara-server
#
#############################################################################
"


# Check if executed as root user
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: This script must be run as root or with sudo" 1>&2
   exit 1
fi

# Prompt user install confirmation
echo "# "
read -p "# Continue install (y/n): " CONT
if [ "$CONT" != "y" ]; then
	exit 1
fi


# Checking if it is a debian based distro
if [ -f "/etc/debian_version" ]; then
	
	CAN_I_RUN_SUDO=$(sudo -n uptime 2>&1|grep "load"|wc -l)
	
	if ! [ ${CAN_I_RUN_SUDO} -gt 0 ]
	then
		echo "#  Could not execute sudo command" 1>&2
		echo "#  Try installing sudo before executing build script"
		exit 1		
	fi
			
	# # Check if mysqld is installed
	# install_mysqld=true
	# if [ -f $(which mysqld) ]; then
		# echo "#  MySQL-Server already installed" 1>&2
		# install_mysqld=false
	# fi
	
	# # Check if nginx is installed
	# install_nginx=true
	# if [ -f $(which nginx) ]; then
		# echo "#  NGINX already installed" 1>&2
		# install_nginx=false
	# fi
	
	
	#export DEBIAN_FRONTEND=noninteractive
	
	#echo -n 'Set the new password for the MySQL "root" user: and press [ENTER]: '
	#read mysql_root_pw
	
	#echo -n ""
	
	# Getting OS distro info
	OS=$(lsb_release -si)
	OSNAME=$(lsb_release --codename|cut -f2)
	ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
	VER=$(lsb_release -sr)
		
	
	
	echo "#  Updating packages"
	sudo apt-get -qq update
	
	echo "#  Creating directory /opt/hipara"
	sudo mkdir -p /opt/hipara
	
	echo "#  Changing current working directory to /opt/hipara"
	cd /opt/hipara
	
	echo "#  Installing dependencies..."
		
	sudo apt-get install git curl apt-utils apt-transport-https ca-certificates -y > /dev/null
	
	echo "#  Starting Docker install"
	sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D > /dev/null
	sudo echo deb https://apt.dockerproject.org/repo ubuntu-xenial main| sudo tee --append /etc/apt/sources.list.d/docker.list

	echo "#   Installing docker engine"
	sudo apt-get -qq update && sudo apt-get install docker-engine -y > /dev/null
	
	echo "#   Installing docker-compose"
	curl -L https://github.com/docker/compose/releases/download/1.8.0/docker-compose-`uname -s`-`uname -m` > docker-compose
	chmod +x docker-compose
	sudo mv docker-compose /usr/local/bin/
	
	echo "#  Cloning HIPARA git repo"
	sudo git clone https://github.com/jbc22/hipara-server.git ./
	sudo git checkout demo-server
	
	sudo mv hipara/hipara/demo_settings.py hipara/hipara/settings.py

	echo "#  Setting IPV6 Forwarding"
	sudo sysctl -w net.ipv6.conf.all.forwarding=1

	echo -e "
################## GRR Rapid Response (GRR) settings ######################

You will be prompted to input the following configuration variable for GRR.

EXTERNAL_HOSTNAME  - This is a value represented in either an IP address or
					 a fully qualified domain name (FQDN)

					 GRR Clients must be able to reach this IP address/fqdn

					 EX: 10.0.0.54 or demo.hipara.org

#############################################################################

"

	while : ; do
		read -p "# Please enter the EXTERNAL_HOSTNAME: " EXTERNAL_HOSTNAME
		if [ "$EXTERNAL_HOSTNAME" ]; then
			break
		fi
		echo "Error: EXTERNAL_HOSTNAME not set"
	done

	echo EXTERNAL_HOSTNAME=$EXTERNAL_HOSTNAME >> grr/.env
	echo GRR_HOST_URL=http://$EXTERNAL_HOSTNAME:8001 >> .env

	echo "# Starting Docker image build"
	docker-compose up --build -d
	
	echo -e "
	# Installation complete!
	#
	# This install is not meant for production use. Please review deployments
	# instructions for production use at: 
	#   https://github.com/jbc22/hipara-server/
	# 
	# To view demo sever, navigate to http://$EXTERNAL_HOSTNAME:8000
	#
	# To view the GRR admin UI, navigate to http://$EXTERNAL_HOSTNAME:8001
	#
	# The default credentials are as follows:
	#
	# Superadmin
	# User: user@hipara.org
	# Password: changedefaultpassword
	#
	# Admin
	# User: demo@hipara.org
	# password: hiparademo
	#
	# GRR
	# User: admin
	# password: hiparaserver
	#
	# Ports used:
	#  - 8000 (HIPARA Django instance)
	#  - 8001 (GRR Admin UI)
	#  - 8080 (GRR Client port)
	#
	#
	# To view docker container logs use this command in the /opt/hipara directory::
	# sudo docker-compose logs
	#
	# To stop the demo server run the following in the /opt/hipara directory:
	# sudo docker-compose down
	#
	#
	# Thanks for trying HIPARA!
	#############################################################################
	"
	
fi

exit 1