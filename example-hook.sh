#!/bin/sh

# Example hook script
# Copy privkey and fullchain to an internal server

SSH_ADDR='root@internal.example.lan'
SSH_COMMAND='systemctl restart nginx.service'
SSH_KEY='/hooks/id_ed25519'
SSH_OPTS='-o StrictHostKeyChecking=accept-new'
REMOTE_PATH='/etc/nginx/certs'

[ -f "${SSH_KEY}" ] || exit 3

CERT_DIR=$1
EVENT=$2
DOMAIN=$3

case ${EVENT} in
  "update")
    case ${DOMAIN} in
      "example.com")
        scp ${SSH_OPTS} -i ${SSH_KEY} ${CERT_DIR}/${DOMAIN}/privkey.pem ${SSH_ADDR}:${REMOTE_PATH}/privkey.pem
        scp ${SSH_OPTS} -i ${SSH_KEY} ${CERT_DIR}/${DOMAIN}/fullchain.pem ${SSH_ADDR}:${REMOTE_PATH}/fullchain.pem

        ssh ${SSH_OPTS} -i ${SSH_KEY} ${SSH_ADDR} ${SSH_COMMAND} || exit 99
      ;;
      *)
        echo "This script will not trigger for domain ${DOMAIN}"
      ;;
    esac
  ;;
  *)
    echo "No handler for event ${EVENT}"
  ;;
esac

exit 0