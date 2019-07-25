#!/usr/bin/env bash
export VAULT_ADDR=http://localhost:8200

docker pull vault
docker stop $(docker inspect --format="{{.Id}}" dev-vault)
docker rm $(docker inspect --format="{{.Id}}" dev-vault)
export VAULT_TOKEN="d0ba0371-5a96-44cb-8ae1-97c54dd54957"
docker run -e SKIP_SETCAP=true --cap-add IPC_LOCK -d -e "VAULT_DEV_ROOT_TOKEN_ID=$VAULT_TOKEN" --name=dev-vault -p 8200:8200 vault
sleep 5

# ========================================================
# == Mount and configure the pki backend =================
# ========================================================
curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @- \
     ${VAULT_ADDR}/v1/sys/mounts/pki <<EOF
{
  "type": "pki",
  "config": {
    "max_lease_ttl": "8760h"
  }
}
EOF

curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @- \
    ${VAULT_ADDR}/v1/pki/root/generate/internal <<EOF
{
  "common_name": "example.com",
  "ttl": "8760h"
}
EOF

curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @- \
     ${VAULT_ADDR}/v1/pki/config/urls <<EOF
{
  "issuing_certificates": "${VAULT_ADDR}/v1/pki/ca",
  "crl_distribution_points": "${VAULT_ADDR}/v1/pki/crl"
}
EOF

# ========================================================
# == Add a role from example-com =========================
# ========================================================
curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @- \
    ${VAULT_ADDR}/v1/pki/roles/my-role <<EOF
{
  "allowed_domains": "example.com",
  "allow_subdomains": true,
  "max_ttl": "72h"
}
EOF
