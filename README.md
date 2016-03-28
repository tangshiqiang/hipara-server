														Hipara

	Initial Setup

		Install python > 3.4 with all dependencies like setuptools
		Install python-virtualenv
		MySql Database

	Create virtual Envirnment at path /source/
		virtualenv env

	Use virtual Environment using command at directory /source/
		source env/bin/activate
		pip install -r requirements.txt

	Update database username, password, database-name in /source/hipara/hipara/settings.py
		Database should be available at given host and port

	Also change the Mail settings Default is filebased

	Then go to path in virtual environment terminal /source/hipara/
		python manage.py migrate

	Super Admin Credentials :
		Username : Admin
		Email : user@hipara.org
		Password : changedefaultpassword

	Execute command to run server
		python manage.py runserver ip_address:port_number


