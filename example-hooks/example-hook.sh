#!/bin/sh
cd $(dirname $0)

ACTION=$1
shift

case $ACTION in
  "pre_cert"|"post_cert")
    DOMAIN=$1
    DIRECTORY=$2
    case $ACTION in
      "pre_cert"|"post_cert")
        PRIVKEY=${DIRECTORY}/privkey.pem
        CERT=${DIRECTORY}/cert.pem
        CHAIN=${DIRECTORY}/chain.pem
        FULLCHAIN=${DIRECTORY}/fullchain.pem
        COMBINED=${DIRECTORY}/combined.pem
        PARAMS="${PRIVKEY} ${CERT} ${FULLCHAIN} ${CHAIN} ${COMBINED}"
      ;;
    esac
    if [ -f "./${ACTION}/${DOMAIN}.sh" ] ; then
      source ./${ACTION}/${DOMAIN}.sh ${PARAMS} || exit 2
    else
      echo "Script ${ACTION}/${DOMAIN}.sh not found"
    fi
  ;;
  # "pre_run")
  # ;;
  # "post_run")
  # ;;
  "*")
    echo "Unknown action: ${ACTION}"
    exit 1
  ;;
esac

exit $?
