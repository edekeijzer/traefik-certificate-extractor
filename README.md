# Traefik Certificate Extractor

Tool to extract ACME certificates from [Traefik](https://traefik.io/).

Originaly developed by [Daniel Huisman](https://github.com/DanielHuisman/traefik-certificate-extractor) and improved by [Marc Brückner](https://github.com/SnowMB) and [Estivador](https://github.com/Estivador/traefik-certificate-extractor), inspired by parts of their code but mostly rewritten.

## Usage

All development and testing was done in Docker, so that's the recommended way to use it: [edekeijzer/traefik-certificate-extractor](https://hub.docker.com/r/edekeijzer/traefik-certificate-extractor/).
Example run:
```shell
docker run --name extractor -d \
  -v /opt/traefik:/app/input \
  -v ./certs:/app/output \
  -v /run/docker.sock:/run/docker.sock \
  edekeijzer/traefik-certificate-extractor:latest
```
Mount the whole folder containing the traefik certificate file (`acme.json`) as `/app/input`. The extracted certificates are going to be written to `/app/output`. The filenames are equal to those produced by certbot (and other ACME clients), as well as a `combined.pem` containing both private key and the public certificate chain.

The Docker socket is used to find any containers with this label: `traefik-certificate-extractor.domains` and will take action if any of the (comma separated) domains matches any domain on the certificate. If the label `traefik-certificate-extractor.command` is set, executing this command within the container will be attempted instead of just restarting it. The special commands `SIGHUP` and `SIGINT` will trigger a `docker kill --signal <signal>>`.

## Configuration

Everything is (currently) configured by environment variables. All variables are optional, with sensible defaults.

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| INPUT_FILE | file path (`string`) | `/app/input/acme.json` | The input file to read certificates from |
| OUTPUT_DIR | dir path (`string`) | `/app/output` | The output directory to write the extracted certificates into |
| OUTPUT_PATH_RESOLVER | `bool` or `none` | `none` | If true, the resolver name will be part of the directory path. If unset, will be true if there are multiple resolvers, false otherwise. |
| HOOK_DIR | dir path (`string`) | `/app/hooks` | The path where hook scripts can be placed |
| CHECK_HASH | `bool` | `true` | Should we do a hash compare on the data from Traefik and the target file before writing (and triggering hooks) |
| ONESHOT | `bool` | `false` | Don't keep running, just do a single process and exit |
| STARTUP_EXTRACT | `bool` | `true` | Should we process immediately at startup or only act at changes while already running? |
| DOCKER_DOMAIN_LABEL | `string` | `traefik-certificate-extractor.domains` | The Docker container label to check for domain names |
| DOCKER_COMMAND_LABEL | `string` | `traefik-certificate-extractor.command` | The Docker container label to check for the command to execute on the container |

## Hooks

The container will fire hooks whenever the input file has been changed:
| Event | Description | Parameters |
| --- | --- | --- |
| pre | Triggered as soon as a file change is detected, before any processing | none |
| pre-cert | Triggered for each certificate, before any check or action | resolver (string), domains (list) |
| update | Triggered for each certificate, after certificate files have been written | resolver (string), domains (list), cert_dir (string), file_names (dict) |
| post | Triggered after all certificates in all resolvers have been processed | none |