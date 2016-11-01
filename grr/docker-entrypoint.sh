#!/bin/bash

# Entrypoint script for GRR docker components.
# If specific components aren't specified this script will initialize the GRR
# server and run all components inside the same container.

set -e

run_component() {
  COMPONENT=$1; shift
  grr_server --component "${COMPONENT}" --disallow_missing_config_definitions "$@"
}

initialize() {
  if [ ! -e "${VIRTUALENV}/install_data/etc/server.local.yaml" ]; then
    if [ $EXTERNAL_HOSTNAME ] && [ $ADMIN_PASSWORD ]; then
      grr_config_updater initialize --noprompt --no_templates_download --external_hostname="$EXTERNAL_HOSTNAME" --admin_password="$ADMIN_PASSWORD"
    else
      echo "initialize hasn't run and EXTERNAL_HOSTNAME/ADMIN_PASSWORD not set"
      exit 1
    fi
  fi
}

checkclientbin() {
 if [ ! -f /usr/share/grr-server/executables/installers/GRR_*_amd64.exe ]; then
  echo "Repacking clients..."
  grr_config_updater repack_clients
  echo "Client repack complete"
 fi
}

APPLICATION=$1;
VIRTUALENV="/usr/share/grr-server/"
if [ ${APPLICATION} = 'grr' ]; then
  source "${VIRTUALENV}/bin/activate"

  if [ "$#" -eq 1 ]; then
    # Run all components in the same container. This is only useful for
    # testing and very small deployments.
    initialize
    checkclientbin
    echo "GRR Admin UI gui is at http://${EXTERNAL_HOSTNAME}:8001, GRR clients will poll to http://${EXTERNAL_HOSTNAME}:8080"
    run_component http_server &
    run_component ui &
    run_component worker &
    run_component worker &
    run_component worker &
    run_component worker
  else
    # TODO(user): this won't actually work yet. Need to solve the problem of
    # getting the initialized config to each component.
    COMPONENT=$2; shift 2
    run_component ${COMPONENT} "$@"
  fi
else
  exec "$@"
fi