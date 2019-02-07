# Traefik Certificate Extractor

Tool to extract Let's Encrypt certificates from [Traefik](https://traefik.io/)'s ACME storage file. Can automatically restart containers using the Docker API.

Originaly developed by [Daniel Huisman](https://github.com/DanielHuisman/traefik-certificate-extractor) and improved by [Marc Brückner](https://github.com/SnowMB).

## Installation
```shell
git clone https://github.com/Estivador/traefik-certificate-extractor
cd traefik-certificate-extractor
```

## Usage
```shell
usage: extractor.py [-h] [-c CERTIFICATE] [-d DIRECTORY] [-f] [-r] [--dry-run]
                    [--include [INCLUDE [INCLUDE ...]] | --exclude
                    [EXCLUDE [EXCLUDE ...]]]

Extract traefik letsencrypt certificates.

optional arguments:
  -h, --help            show this help message and exit
  -c CERTIFICATE, --certificate CERTIFICATE
                        file that contains the traefik certificates (default
                        acme.json)
  -d DIRECTORY, --directory DIRECTORY
                        output folder
  -f, --flat            outputs all certificates into one folder
  -r, --restart_container
                        uses the docker API to restart containers that are
                        labeled accordingly
  --dry-run             Don't write files and do not start docker containers.
  --include [INCLUDE [INCLUDE ...]]
  --exclude [EXCLUDE [EXCLUDE ...]]
```
Default file is `./data/acme.json`. The output directories are `./certs` and `./certs_flat`.

## Docker
There is a Docker image available for this tool: [estivadorio/traefik-certificate-extractor](https://hub.docker.com/r/estivadorio/traefik-certificate-extractor/).
Example run:
```shell
docker run --name extractor -d \
  -v /opt/traefik:/app/data \
  -v ./certs:/app/certs \
  -v /var/run/docker.socket:/var/run/docker.socket \
  estivadorio/traefik-certificate-extractor 
```
Mount the whole folder containing the traefik certificate file (`acme.json`) as `/app/data`. The extracted certificates are going to be written to `/app/certs`. Additionally this script will export combined key and cert into `combined.pem` file that can be used, i.e., for [Cockpit](https://cockpit-project.org) by correctly linking it to its certificate store.

The Docker socket is used to find any containers with this label: `com.github.Estivador.traefik-certificate-extractor.restart_domain=<DOMAIN>`.
If the domains of an extracted certificate and the restart domain matches, the container is restarted. Multiple domains can be given seperated by `,`.

## Output
```
certs/
    example.com/
        cert.pem
        chain.pem
        combined.pem
        fullchain.pem
        privkey.pem
    sub.example.nl/
        cert.pem
        chain.pem
        combined.pem
        fullchain.pem
        privkey.pem
certs_flat/
    example.com.crt
    example.com.key
    example.com.chain.pem
    sub.example.nl.crt
    sub.example.nl.key
    sub.example.nl.chain.pem
```
