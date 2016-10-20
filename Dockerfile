# Dockerfile -- deploys django files for HIPARA demo server
#	by Tin Tam <tin@hipara.org>
#

# Use the python 3.4 image
FROM python:3.4

# Map the hipara django directory 
ADD ./hipara /app
ADD ./requirements.txt /app/requirements.txt
ADD ./run_web.sh /app/run_web.sh

# Set working directory to /app/
WORKDIR /app

# Install python3 dependencies
RUN pip3 install -r requirements.txt

# Install packages
RUN apt-get update && apt-get install netcat -y

# Adding unprivileged celery user
RUN adduser --disabled-password --gecos '' celery

# Adding PID dir to /var/run
RUN mkdir -p /var/run/celery

# Adding Log dir to /var/log
RUN mkdir -p /var/log/celery

# Set permissions for celery user for PID and log dir
RUN chown celery:celery /var/run/celery
RUN chown celery:celery /var/log/celery

