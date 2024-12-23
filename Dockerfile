# Use Python on Alpine Linux as base image
FROM python:alpine

RUN apk add --no-cache dropbear dropbear-ssh dropbear-scp
WORKDIR /app

# Copy requirements.txt to force Docker not to use the cache
COPY requirements.txt /app

# Install app dependencies
RUN pip3 install -r requirements.txt

# Copy app source
COPY extractor.py /app

# Define entrypoint of the app
ENTRYPOINT ["python3", "-u", "extractor.py"]
CMD ["-c", "data/acme.json", "-d", "certs"]
