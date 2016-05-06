														Hipara

	Initial Setup

		Install python > 3.4 with all dependencies like setuptools
		Install python-virtualenv
		MySql Database

	Create virtual Envirnment at path /hipara-server/
		virtualenv env

	Use virtual Environment using command at directory /hipara-server/source/
		source env/bin/activate
		pip install -r requirements.txt

	Update database username, password, database-name in /hipara-server/hipara/hipara/settings.py
		Database should be available at given host and port

	Also change the Mail settings Default is filebased

	Super Admin Credentials :
		Username : Admin
		Email : user@hipara.org
		Password : changedefaultpassword

	if you want to change it then update it in 
	  /hipara-server/hipara/registration/migrations/0002_auto20151202_1245.py


	Then go to path in virtual environment terminal /hipara-server/hipara/
		python manage.py migrate

	

	Execute command to run server
		python manage.py runserver ip_address:port_number


