# Tested on Ubuntu 14.04 'Trusty' only.

#move to /opt dir & setup
mkdir /opt/hipara/
cd /opt/hipara/
virtualenv hiparaenv
cp -R ~/YaraManager/* /opt/hipara/hiparaenv/
cp /opt/hipara/hiparaenv/secret_key.py /opt/hipara/hiparaenv/source/hipara
source /opt/hipara/hiparaenv/bin/activate

#download & install dependencies
apt-get install libmysqlclient-dev python-dev
sudo apt-get install libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk
pip install django MySQL-python
pip install Pillow
pip install -r hiparaenv/source/requirements.txt 

#initiate web app
python /opt/hipara/hiparaenv/source/hipara/manage.py migrate
python /opt/hipara/hiparaenv/source/hipara/manage.py createsuperuser
