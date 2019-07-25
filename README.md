# Vault Certificate cookbook [![license](https://img.shields.io/badge/license-Apache%20v2-blue.svg)](LICENSE)

[![Build Status](https://travis-ci.org/ist-dsi/cookbook-vault-certificate.svg?branch=master)](https://travis-ci.org/ist-dsi/cookbook-vault-certificate)

Chef library cookbook to manage SSL certificates fetched from HashiCorp Vault.

### Requirements

A working Vault server to talk to.

### Platforms

Tested on:

- CentOS
- Debian
- Ubuntu
- Fedora

### Chef

- Chef 14.10+

## Resources

### vault_certificate

This resource is able to fetch ssl certificates, their corresponding chain and private key from HashiCorp Vault.

Using the default settings, the following usage:

```ruby
vault_certificate 'example-service.example.com'
```

Fetches the certificate from Vault by performing a write on `pki/issue/my-role common_name=example-service.example.com`.

You must configure the how to talk to Vault using the settings from the [vault-ruby gem](https://github.com/hashicorp/vault-ruby).
Example for [Vault agent](https://www.vaultproject.io/docs/agent/index.html) configured with a listener at `127.0.0.1:8200` without tls:

```
Vault.address = 'http:/127.0.0.1:8200'
Vautl.ssl_verify = false
```

#### .certificate, .key, .chain helper method usage

Some helper methods are exposed for retrieving key/certificate paths in other recipes:

  - `.certificate` - The final path of the certificate file. For example using the defaults and on CentOS: `/etc/pki/tls/certs/example-service.example.com.pem`.
  - `.key` - The final path of the key file. For example using the defaults and on CentOS: `/etc/pki/tls/private/example-service.example.com.key`
  - `.chain` - The final path of the chain file. For example using the defaults and on CentOS: `/etc/pki/tls/certs/example-service.example.com-bundle.pem`

```ruby
certificate = vault_certificate 'example-service.example.com' do
  combine_certificate_and_chain true # Because we will be using the certificate on Nginx.
end

nginx_site 'proxy' do
  template 'proxy.erb'
  variables(
    'certificate' => certificate
  )
  action :enable
end
```

Then in `proxy.erb`:

```
server {
  listen                443 ssl http2;
  listen                [::]:443 ssl http2;
  server_name           example-service.example.com;
  
  ssl_certificate       <%= @certificate.certificate %>;
  ssl_certificate_key   <%= @certificate.key %>;
}
```

See the list of properties bellow.

#### General properties

  - `common_name` - CN of the certificate. Default value: the name of the resource block.
  - `vault_path` - the path used to get the certificate from Vault.
  - `options` - the options to pass Vault when asking for a certificate. If set to an empty Hash a vault read will be performed.
                Otherwise a vault write. Default: `{ common_name: "#{common_name}" }`.
  - `output_certificates` - if set false the certificate/chain content will not be logged in the Chef run.
                            The files will be generated with sensitive set to true. Default: true.
  - `always_ask_vault` - if set to true vault_certificate will always ask Vault for a certificate. Otherwise it will check whether
                         the certificate and key exist in the file system and if the certificate is still valid.
                         Only when the certificate is invalid (probably because it has expired) will vault_certificate ask Vault for a certificate.
                         Default: false.

#### Certificate bundles properties

  - `combine_certificate_and_chain` - whether to combine the certificate and the CA trust chain in a single file in that
                                      order. Useful to use in Nginx. Default: `false`.
  - `combine_all` - whether to combine the certificate, the CA trust chain, and the private key in a single file in that
                    order. Useful to use in HAProxy. Default: `false`.

#### Stores (PKCS12 and Java) properties
  
  - `store_path` - the top-level directory where stores will be created.
  - `store_password` - the password used to protected the store.
  - `key_encryption_password` - the password used to encrypt the key inside the store.
                                If not set, set to nil or set to empty string the key will not be encrypted.
  - `key_encryption_cipher` - the cipher used to encrypt the key.
  - `keystore_password` - the password for the keystore. By default the same as store_password.
                          Having a separate property for the keystore password allows having different passwords for the
                          keystore and the truststore when using the action create_key_and_trust_stores.
  - `keystore_filename` - the filename the keystore will have on the filesystem. Default "#{common_name}.keystore.jks".
  - `truststore_password` - the password for the truststore. By default the same as store_password.
                            H**aving a separate property for the truststore password allows having different passwords for the
                            keystore and the truststore when using the action create_key_and_trust_stores.
  - `truststore_filename` - the filename the truststore will have on the filesystem. Default "#{common_name}.truststore.jks".
  - `pkcs12store_filename` - the filename the pkcs12 store will have on the filesystem. By default "#{common_name}.pkcs12".

#### Filesystem properties

  - `ssl_path` - directory where the certificates, chains, and keys will be stored. The final path might be different depending on `create_subfolders`.
                 The default is SO dependent, see [attributes](attributes/defaults.rb) for the final value.
  - `create_subfolders` - whether to create `certs` and `private` sub-folders inside `ssl_path`.
                          The default is SO dependent, see [attributes](attributes/defaults.rb) for the final value.
  - `certificate_filename` - filename of the certificate. Default: `"#{common_name}.pem"`.
  - `chain_filename` - filename of the CA chain bundle. Default: `"#{common_name}-bundle.crt"`.
  - `key_filename` - filename of the private key. Default: `"#{common_name}.key"`.
  - `owner` - owner of the subfolders, the certificate, the chain and the private key. Default: `root`.
  - `group` - group of the subfolders, the certificate, the chain and the private key. Default: `root`.

## Attributes

In order to promote code reuse most of the properties can be defined via an attribute. This allows, for example, to define
the Vault `address` and `token` just once without the need to explicitly define it for every invocation of `vault_certificate`:

```ruby
node.normal['vault_certificate']['always_ask_vault'] = false

vault_certificate 'example-service.example.com'
vault_certificate 'db.example-service.example.com'
```

See the [attributes file](attributes/defaults.rb) for a full list of supported attributes.

## Actions

  - `create` - the default action. Creates the certificate, private key and chain.
  - `create_pkcs12_store` - creates a PKCS12 store on `store_path` and `store_password`.
  - `create_keystore` - creates a Java keystore using `keytool` (you must have it installed if you have java installed it will be installed).
  - `create_truststore` - creates a Java truststore using `keytool` (you must have it installed if you have java installed it will be installed).
  - `create_key_and_trust_stores` - creates a Java keystore and a truststore in one go. It is more efficient since it just makes a request to Vault.

## License
vault_certificate is open source and available under the [Apache v2 license](LICENSE).