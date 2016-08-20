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

# Run the Django runserver
CMD /bin/sh -c "./run_web.sh"