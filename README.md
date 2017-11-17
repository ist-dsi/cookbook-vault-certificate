Vault Certificate cookbook
==========================

[![Build Status](https://travis-ci.org/ist-dsi/cookbook-vault-certificate.svg?branch=master)](https://travis-ci.org/ist-dsi/cookbook-vault-certificate)

Chef library cookbook to manage SSL certificates fetched from HashiCorp Vault.

### Platforms

Tested on:

- CentOS
- Debian
- Ubuntu
- Fedora

### Chef

- Chef 12.8+

## Resources

### vault_certificate

This resource is able to fetch ssl certificates, their corresponding chain and private key from HashiCorp Vault.

#### Service properties
Property                      | Description                                                                                        | Example                                  | Default
----------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------
certificate_common_name       | CN of the certificate.                                                                             | example-service.example.com              | Resource name
service_name                  |                                                                                                    | example-service                          | Must be specified.
environment                   |                                                                                                    | staging                                  | node.environment
version                       |                                                                                                    | v1-2017-10-15                            | Empty string.
static_environments           | if environment matches any regex in `static_environment` then `static_path` will be used. Otherwise `dynamic_path` will be used. | [/staging-\d+/, /production | [/production/, /staging/]

#### Vault properties
Property | Description                                              | Example                                  | Default
---------| ---------------------------------------------------------| ---------------------------------------- | ---------------------
address  | the address of the Vault Server                          | https://my-vault.example.com             | http://127.0.0.1:8200
token    | the token used to authenticate against the Vault Server. | efad6fc1-bf37-7a10-fb78-67ae8756c219     | nil

#### Static environment properties
Property          | Description                                                                                           | Example   | Default
----------------- | ----------------------------------------------------------------------------------------------------- | --------- | ---------------------
static_mountpoint | the Vault mountpoint used for static environments.                                                    | 'secret'  | 'secret'
common_path       | the path to use in `static_path` when `use_common_path` is set to true.                               | 'common'  | 'common'
use_common_path   | whether to use `common_path` in `static_path`.                                                        | true      | true
certificates_path | the last path to use in `static_path`. This allows having multiple certificates for a single service. | 'certs'   | 'certificates'
static_path       | the full path used to get the certificate from Vault.                       | 'secret/example-service/staging/common/certificates/example-service.example.com' | Explained below.

#### Dynamic environment properties
Property           | Description                                              | Example                     | Default
------------------ | -------------------------------------------------------- | --------------------------- | ---------------------
dynamic_mountpoint | the Vault mountpoint used for dynamic environments.      | 'pki/issue'                 | 'pki/issue'
pki_role           | the role used in Vault pki to generate new certificates. | 'example-dot-com'           | nil. On dynamic environments it must be specified.
dynamic_path       | the full path used to get the certificate from Vault.    | 'pki/issue/example-dot-com' | Explained below.
dynamic_options    | the options to pass to the pki Vault backend.            | `{ common_name: "#{certificate_common_name}", private_key_format: 'pkcs8' }` | `{ common_name: "#{certificate_common_name}" }`

#### Certificate bundles properties
Property                      | Description                                                                                                                           | Example | Default
----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------- | ---------------------
combine_certificate_and_chain | whether to combine the certificate and the CA trust chain in a single file in that order. Useful to use in Nginx.                     | true    | false
combine_all                   | whether to combine the certificate, the CA trust chain, and the private key in a single file in that order. Useful to use in HAProxy. | true    | false

#### Filesystem properties
Property          | Description                                                              | Example                                 | Default
----------------- | ------------------------------------------------------------------------ | --------------------------------------- | ---------------------
ssl_path          | directory where the certificates, chains, and keys will be stored.       | '/etc/pki/tls'                          | The default value is SO dependent.
create_subfolders | whether to create 'certs' and 'private' sub-folders inside `ssl_path`.   | true                                    | The default value is SO dependent.
certificate_file  | filename of the certificate.                                             | "#{certificate_common_name}.pem"        | "#{certificate_common_name}.pem"
chain_filename    | filename of the CA chain bundle.                                         | "#{certificate_common_name}-bundle.crt" | "#{certificate_common_name}-bundle.crt"
key_filename      | filename of the private key.                                             | "#{certificate_common_name}.key"        | "#{certificate_common_name}.key"
owner             | owner of the subfolders, the certificate, the chain and the private key. | 'root'                                  | 'root'
group             | group of the subfolders, the certificate, the chain and the private key. | 'root'                                  | 'root'

