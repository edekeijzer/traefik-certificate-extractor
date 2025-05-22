#!/bin/sh
SSH_ADDR='root@octoprint.fscker.lan'
SSH_COMMAND='systemctl restart nginx.service'
SSH_KEY='../id_ed25519'
SSH_OPTS='-o StrictHostKeyChecking=accept-new'
REMOTE_PATH='/etc/nginx'

[ -f "${SSH_KEY}" ] || exit 3

CERT_DIR=$1
DOMAIN=$2

case ${DOMAIN} in
  "fscker.nl")
    scp ${SSH_OPTS} -i ${SSH_KEY} ${CERT_DIR}/${DOMAIN}/privkey.pem ${SSH_ADDR}:${REMOTE_PATH}/privkey.pem
    scp ${SSH_OPTS} -i ${SSH_KEY} ${CERT_DIR}/${DOMAIN}/fullchain.pem ${SSH_ADDR}:${REMOTE_PATH}/fullchain.pem

    ssh ${SSH_OPTS} -i ${SSH_KEY} ${SSH_ADDR} ${SSH_COMMAND} || exit 99
  ;;
  *)
    echo "No handler for ${DOMAIN}"
  ;;
esac