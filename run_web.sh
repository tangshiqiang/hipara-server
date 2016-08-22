# run_web.sh -- deploys django for HIPARA demo server
#	by Tin Tam <tin@hipara.org>
#

# Check to see if the database is up and running
until nc -z $DJANGO_MYSQL_HOST $DJANGO_MYSQL_PORT; do
	echo "$(date) - waiting for mysql..."
	sleep 1
done

# Migrate the database
/bin/sh -c "python manage.py migrate"

# Collect static files
/bin/sh -c "python manage.py collectstatic --noinput"


# Start the django web interface
/bin/sh -c "python manage.py runserver 0.0.0.0:8000"