# Use Python on Alpine Linux as base image
FROM python:3.12-alpine

# Add ssh tools so we can copy certs to remote locations
RUN apk add --no-cache dropbear dropbear-ssh dropbear-scp
WORKDIR /app

# Copy requirements.txt to force Docker not to use the cache
COPY requirements.txt /app

# Install app dependencies
RUN pip3 install -r requirements.txt

# Copy app source
COPY app/ /app

# Define entrypoint of the app
ENTRYPOINT ["python3", "-u", "/app/main.py"]
CMD []