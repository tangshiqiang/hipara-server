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

# Error exit function
function error_exit
{
	echo "$1" 1>&2
	exit 1
}

# Trapping Ctrl-C
function ctrl_c() {
	echo "Exiting: CTRL-C command issued"
	exit 1
}
trap ctrl_c INT


# Check if executed as root user
if [ "$(id -u)" != "0" ]; then
   error_exist "ERROR: This script must be run as root or with sudo"
fi

# Prompt user install confirmation
echo "# "
read -p "# Continue install (y/n): " CONT
if [ "$CONT" != "y" ]; then
	error_exit "Exiting Installation"
fi


# Checking if it is a debian based distro
if [ ! -f "/etc/debian_version" ]; then
	error_exit "Error: Operating system is not a debian based."
fi
	
CAN_I_RUN_SUDO=$(sudo -n uptime 2>&1|grep "load"|wc -l)
	
if ! [ ${CAN_I_RUN_SUDO} -gt 0 ]
then
	echo "#  Could not execute sudo command" 1>&2
	echo "#  Try installing sudo before executing build script"
	exit 1
fi
	
# Getting OS distro info
OS=$(lsb_release -si)
OSNAME=$(lsb_release --codename|cut -f2)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

echo "#  Updating packages"
sudo apt-get -qq update
if [ "$?" != "0" ]; then error_exit "Error: unable to update packages"; fi

echo "#  Creating directory /opt/hipara"
sudo mkdir -p /opt/hipara
if [ "$?" != "0" ]; then error_exit "Error: unable to create directory /opt/hipara"; fi

echo "#  Changing current working directory to /opt/hipara"
cd /opt/hipara
if [ "$?" != "0" ]; then error_exit "Error: unable to access /opt/hipara"; fi

echo "#  Installing dependencies..."
sudo apt-get -qq install git curl apt-utils apt-transport-https ca-certificates -y
if [ "$?" != "0" ]; then error_exit "Error: unable to install dependencies"; fi

echo "#  Starting Docker install"
sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
if [ "$?" != "0" ]; then error_exit "Error: unable to add public key for docker "; fi

# Check to see if docker APT source file exists
if sudo cat /etc/apt/sources.list.d/docker.list; then
	sudo rm /etc/apt/sources.list.d/docker.list
fi
sudo echo deb https://apt.dockerproject.org/repo ${OS,,}-$OSNAME main| sudo tee --append /etc/apt/sources.list.d/docker.list
if [ "$?" != "0" ]; then error_exit "Error: unable to add apt repo for docker "; fi

echo "#   Installing docker engine"
sudo apt-get -qq update && sudo apt-get -qq install docker-engine -y
if [ "$?" != "0" ]; then error_exit "Error: unable to install docker "; fi

# Check if docker exists
DOCKER_BIN=$(sudo which docker)
if ! [ "$DOCKER_BIN" ]; then error_exit "Error: unable to find the docker binary"; fi

echo "#   Installing docker-compose"
if curl -L -O https://github.com/docker/compose/releases/download/1.8.0/docker-compose-`uname -s`-`uname -m`; then
	if file file docker-compose-`uname -s`-`uname -m`|grep executable; then
		chmod +x docker-compose-`uname -s`-`uname -m`
		sudo mv docker-compose-`uname -s`-`uname -m` /usr/local/bin/docker-compose
	else
		error_exit "Error: unable to download docker-compose"
	fi
else
	error_exit "Error: unable to download docker-compose"
fi


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
