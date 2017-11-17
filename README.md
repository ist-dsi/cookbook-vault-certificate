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

## Usage



## Properties

Property                      | Description                                                                                        | Example                                  | Default
----------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------
certificate_common_name       |                                                                                                    | example-service.example.com              | Resource name
service_name                  |                                                                                                    | example-service                          | Must be specified.
environment                   |                                                                                                    | staging                                  | node.environment
version                       |                                                                                                    | v1-2017-10-15                            | Empty string.
address                       | the address of the Vault Server                                                                    | https://my-vault.example.com             | http://127.0.0.1:8200
token                         | the token used to authenticate against the Vault Server.                                           | root                                     | efad6fc1-bf37-7a10-fb78-67ae8756c219
static_environments           | the list of environments for which the `static_path` will be used to retrieve the Certificate from Vault. This is an array of regexes. If any regex matches then the static_path will be used. | [/staging-\d+/, /production | [/production/, /staging/]
static_mountpoint             | the Vault mountpoint used for static environments.                                                 | 'secret'                                 | 'secret'
common_path                   | the path to use in `static_path` when `use_common_path` is set to true.                            | 'common'                                 | 'common'
use_common_path               | whether to use `common_path` in `static_path`.                                                     | true                                     | true
certificates_path             | the last path to use in `static_path`. This allows having multiple certificates for a single service. | 'certs'                               | 'certificates'
static_path                   | the full path used, in a static environment, to get the certificate from Vault.                    | 'secret/example-service/staging/common/certificates/example-service' | Explained below.
dynamic_mountpoint            | the Vault mountpoint used for dynamic environments.                                                | 'pki/issue'                              | 'pki/issue'
pki_role                      | the role used in Vault pki to generate new certificates.                                           | 'example-dot-com'                        | nil. On dynamic environments it must be specified.
dynamic_path                  | the full path used, in a dynamic environment, to get the certificate from Vault.                   | 'pki/issue/example-dot-com'              | Explained below.
dynamic_options               | the options to pass to the pki Vault backend.                                                      | `{ common_name: "#{certificate_common_name}", private_key_format: 'pkcs8' }` | `{ common_name: "#{certificate_common_name}" }`
combine_certificate_and_chain | whether to combine the certificate and the CA trust chain in a single file in that order. Useful to use in Nginx. | true | false
combine_all                   | whether to combine the certificate, the CA trust chain, and the private key in a single file in that order. Useful to use in HAProxy. | true | false
ssl_path                      | the top-level directory in the filesystem where the certificates, chains, and keys will be stored. | '/etc/pki/tls' | The default value is SO dependent.
create_subfolders             | whether to create 'certs' and 'private' sub-folders inside `certificate_path`.                     | true | The default value is SO dependent.
certificate_file              | the filename the managed certificate will have on the filesystem. | "#{certificate_common_name}.pem" | "#{certificate_common_name}.pem"
chain_filename                | the filename the managed CA chain bundle will have on the filesystem. | "#{certificate_common_name}-bundle.crt" | "#{certificate_common_name}-bundle.crt"
key_filename                  | the filename the managed private key will have on the filesystem. | "#{certificate_common_name}.key" | "#{certificate_common_name}.key"
owner                         | the owner of the subfolders, the certificate, the chain and the private key. | 'root' | 'root'
group                         | the group of the subfolders, the certificate, the chain and the private key. | 'root' | 'root'

