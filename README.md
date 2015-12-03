														Hipara

	Initial Setup

		Install python > 3.4
		Install python-virtualenv
		MySql Database

	Create virtual Envirnment at path /source/
		virtualenv env

	Use virtual Environment using command at directory /source/
		source env/bin/activate
		pip install -r requirements.txt

	Update database username, password, database-name in /source/hipara/hipara/settings.py
		Database should be available at given host and port

	Then go to path in virtual environment terminal /source/hipara/
		python manage.py migrate

	Super Admin Credentials :
		Username : brettcu
		Email : brettcu@gmail.com
		Password : hipara_jbc22

	Execute command to run server
		python manage.py runserver ip_address:port_number


