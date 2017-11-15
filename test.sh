#!/usr/bin/env bash
VAULT_CONTAINER_ID=`docker run --privileged --cap-add IPC_LOCK -d --name=dev-vault -p 8200:8200 vault`
VAULT_ROOT_TOKEN=`docker logs $VAULT_CONTAINER_ID | grep -Po "(?<=Root Token: )([^\n]+)"`


# Mount the secret and pki backends
# Populate vault with some data


foodcritic -f any .
cookstyle -D

kitchen converge all