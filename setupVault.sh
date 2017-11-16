#!/usr/bin/env bash
VAULT_ADDRESS=http://dev-vault:8200

VAULT_CONTAINER_ID=`docker run -e SKIP_SETCAP=true --cap-add IPC_LOCK -d --name=dev-vault -p 8200:8200 vault`
sleep 2
export VAULT_ROOT_TOKEN=`docker logs $VAULT_CONTAINER_ID | grep -Po "(?<=Root Token: )([^\n]+)" | tail -n1`

curl --header "X-Vault-Token: $VAULT_ROOT_TOKEN" \
     --data @- \
     ${VAULT_ADDRESS}/v1/sys/mounts/pki <<EOF
{
  "type": "pki",
  "config": {
    "max_lease_ttl": "8760h"
  }
}
EOF

curl --header "X-Vault-Token: $VAULT_ROOT_TOKEN" \
     --data @- \
    ${VAULT_ADDRESS}/v1/pki/root/generate/internal <<EOF
{
  "common_name": "example.com",
  "ttl": "8760h"
}
EOF

curl --header "X-Vault-Token: $VAULT_ROOT_TOKEN" \
     --data @- \
     ${VAULT_ADDRESS}/v1/pki/config/urls <<EOF
{
  "issuing_certificates": "${VAULT_ADDRESS}/v1/pki/ca",
  "crl_distribution_points": "${VAULT_ADDRESS}/v1/pki/crl"
}
EOF


curl --header "X-Vault-Token: $VAULT_ROOT_TOKEN" \
     --data @- \
    ${VAULT_ADDRESS}/v1/pki/roles/example-com <<EOF
{
  "allowed_domains": "example.com",
  "allow_subdomains": true,
  "max_ttl": "72h"
}
EOF