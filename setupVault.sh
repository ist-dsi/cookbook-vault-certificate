#!/usr/bin/env bash
export VAULT_ADDR=http://localhost:8200

docker pull vault
docker stop $(docker inspect --format="{{.Id}}" dev-vault)
docker rm $(docker inspect --format="{{.Id}}" dev-vault)
docker run -e SKIP_SETCAP=true --cap-add IPC_LOCK -d --name=dev-vault -p 8200:8200 vault
sleep 5
export VAULT_TOKEN=`docker logs $(docker inspect --format="{{.Id}}" dev-vault) | grep --color=never -Po "(?<=Root Token: )([^\n]+)" | tail -n1`

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
    ${VAULT_ADDR}/v1/pki/roles/example-com <<EOF
{
  "allowed_domains": "example.com",
  "allow_subdomains": true,
  "max_ttl": "72h"
}
EOF

# ========================================================
# == Add the static certificates =========================
# ========================================================
curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data-raw '{ "common_name": "test-with-version.example.com" }' \
    ${VAULT_ADDR}/v1/pki/issue/example-com | jq '.data' > test-with-version.example.com.json
curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @test-with-version.example.com.json \
    ${VAULT_ADDR}/v1/secret/example-service/production/v1-2017-11-05/certificates/test-with-version.example.com
rm test-with-version.example.com.json


curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data-raw '{ "common_name": "test-common.example.com" }' \
    ${VAULT_ADDR}/v1/pki/issue/example-com | jq '.data' > test-common.example.com.json
curl --header "X-Vault-Token: $VAULT_TOKEN" \
     --data @test-common.example.com.json \
    ${VAULT_ADDR}/v1/secret/example-service/production/common/certificates/test-common.example.com
rm test-common.example.com.json