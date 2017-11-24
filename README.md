# Vault Certificate cookbook [![license](https://img.shields.io/badge/license-Apache%20v2-blue.svg)](LICENSE)

[![Build Status](https://travis-ci.org/ist-dsi/cookbook-vault-certificate.svg?branch=master)](https://travis-ci.org/ist-dsi/cookbook-vault-certificate)

Chef library cookbook to manage SSL certificates fetched from HashiCorp Vault.

### Requirements

Your Vault server must have a [key-value](https://www.vaultproject.io/docs/secrets/kv/index.html) and a
[pki](https://www.vaultproject.io/docs/secrets/pki/index.html) backend configured.

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

Using the default settings, the following usage fetches the certificate from Vault:

- On path `secret/example-service/production/common/certificates/example-service.example.com`, if the node is in a **static** environment (for example, if we are in `production`)
- With `pki/issue/example-dot-com common_name=example-service.example.com`, if the node is in a **dynamic** environment

```ruby
vault_certificate 'example-service.example.com' do
  service_name 'example-service'
  pki_role 'example-dot-com'
  
  address 'https://my-vault.example.com'
  token 'efad6fc1-bf37-7a10-fb78-67ae8756c219'
end
```

#### .certificate, .key, .chain helper method usage

Some helper methods are exposed for retrieving key/certificate paths in other recipes:

  - `.certificate` - The final path of the certificate file. For example using the defaults and on CentOS: `/etc/pki/tls/certs/example-service.example.com.pem`.
  - `.key` - The final path of the key file. For example using the defaults and on CentOS: `/etc/pki/tls/private/example-service.example.com.key`
  - `.chain` - The final path of the chain file. For example using the defaults and on CentOS: `/etc/pki/tls/certs/example-service.example.com-bundle.pem`

```ruby
cert = vault_certificate 'example-service.example.com' do
  service_name 'example-service'
  pki_role 'example-dot-com'
  combine_certificate_and_chain true # Because we will be using the certificate on Nginx.
 
  address 'https://my-vault.example.com'
  token 'efad6fc1-bf37-7a10-fb78-67ae8756c219'
end


nginx_site 'proxy' do
  template 'proxy.erb'
  variables(
    'certificate' => cert
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
  
#### What constitutes a static/dynamic environment?
`vault_certificate` has a property called `static_environments` which is an array of regexes. If `environment` matches
any of those regexes then the node is considered to be in a static environment. Otherwise it is considered to
be in a dynamic environment.

#### How can I change/customize the paths?
You can either set `static_path` and/or `dynamic_path` and `dynamic_options` directly. Alternately, you can use any of 
the other properties to customize the path. For example if you set `static_mountpoint` to `base-services-secrets` then 
the path for the static environments would be:

  `base-services-secrets/example-service/production/common/certificates/example-service.example.com`

See the list of properties bellow.

#### General properties

  - `certificate_common_name` - CN of the certificate. No default, **this must be specified**.
  - `environment` - the environment on which the node is being provisioned. Default: the chef environment.
  - `static_environments` - an array of regexes used to compute whether the node is being provisioned in a static or dynamic environment.
                            If `environment` matches any of the regexes then `static_path` will be used. Otherwise `dynamic_path` will be used.
                            Default: `[/production/, /staging/]`.

#### Vault properties

  - `address` - the address of the Vault Server. Default: `http://127.0.0.1:8200`.
  - `token` - the token used to authenticate against the Vault Server. No default, **this must be specified**.

#### Static environment properties
  
  - `static_mountpoint` - the Vault mountpoint used for static environments. Default: `secret`
  - `service_name` - the name of the service being provisioned. No default, this must be specified on static environments.
  - `version` - the specific version of the service that is being provisioned. No default, this must be specified when `use_common_path` is false.
  - `common_path` - the path to use in `static_path` when `use_common_path` is set to true. Default: `common`.
  - `use_common_path` - whether to use `common_path` in `static_path`. Default: `true`.
  - `certificates_path` - the last path to use in `static_path`. This allows having multiple certificates for a single service. Default: `certificates`.
  - `static_path` - the full path used to get the certificate from Vault in static environments. Default: using the defaults it would be
                    `secret/example-service/#{node.environment}/common/certificates/#{certificate_common_name}`.

#### Dynamic environment properties
                    
  - `dynamic_mountpoint` - the Vault mountpoint used for dynamic environments. Default: `pki/issue`.
  - `pki_role` - the role used in Vault pki to generate new certificates. No default, this must be specified on dynamic environments.
  - `dynamic_path` - the full path used to get the certificate from Vault in dynamic environments. Default: using the defaults it would be
                     `pki/issue/#{pki_role}`.
  - `dynamic_options` - the options to pass to the pki Vault backend. Default: `{ common_name: "#{certificate_common_name}" }`.

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
  - `keystore_filename` - the filename the keystore will have on the filesystem. Default "#{certificate_common_name}.keystore.jks".
  - `truststore_password` - the password for the truststore. By default the same as store_password.
                            H**aving a separate property for the truststore password allows having different passwords for the
                            keystore and the truststore when using the action create_key_and_trust_stores.
  - `truststore_filename` - the filename the truststore will have on the filesystem. Default "#{certificate_common_name}.truststore.jks".
  - `pkcs12store_filename` - the filename the pkcs12 store will have on the filesystem. By default "#{certificate_common_name}.pkcs12".

#### Filesystem properties

  - `ssl_path` - directory where the certificates, chains, and keys will be stored. The final path might be different depending on `create_subfolders`.
                 The default is SO dependent, see [attributes](attributes/defaults.rb) for the final value.
  - `create_subfolders` - whether to create `certs` and `private` sub-folders inside `ssl_path`.
                          The default is SO dependent, see [attributes](attributes/defaults.rb) for the final value.
  - `certificate_filename` - filename of the certificate. Default: `"#{certificate_common_name}.pem"`.
  - `chain_filename` - filename of the CA chain bundle. Default: `"#{certificate_common_name}-bundle.crt"`.
  - `key_filename` - filename of the private key. Default: `"#{certificate_common_name}.key"`.
  - `owner` - owner of the subfolders, the certificate, the chain and the private key. Default: `root`.
  - `group` - group of the subfolders, the certificate, the chain and the private key. Default: `root`.

## Attributes

In order to promote code reuse most of the properties can be defined via an attribute. This allows, for example, to define
the Vault `address` and `token` just once without the need to explicitly define it for every invocation of `vault_certificate`:

```ruby
node.normal['vault_certificate']['address'] = 'https://my-vault.my-domain.gtld'
node.normal['vault_certificate']['token'] = '<my-token>'

vault_certificate 'example-service.example.com' do
  service_name 'example-service'
  pki_role 'example-dot-com'
end

vault_certificate 'db.example-service.example.com' do
  service_name 'example-service'
  pki_role 'example-dot-com'
end
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