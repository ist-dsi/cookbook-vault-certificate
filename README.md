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

Using the default settings the following usage:

```ruby
vault_certificate 'example-service.example.com' do
  service_name 'example-service'
  pki_role 'example-dot-com'
  
  address 'https://my-vault.example.com'
  token 'efad6fc1-bf37-7a10-fb78-67ae8756c219'
end

```

1) If the node is in a **static** environment (lets assume we are in `production`) the certificate will be fetched from Vault on the path:
  ```secret/example-service/production/common/certificates/example-service.example.com```
2) If the node is in a **dynamic** environment the certificate will be fetched from Vault with:
  ```pki/issue/example-dot-com common_name=example-service.example.com```
  
#### What constitutes a static/dynamic environment?
`vault_certificate` has a property called `static_environments`, which is an array of regexes, if `environment` matches
any of those regexes then the node is considered to be in a static environment otherwise it is considered to
be in a dynamic environment.

#### How can I change/customize the paths?
You can either set `static_path` and/or `dynamic_path` and `dynamic_options` directly. Or you can use any of the other
properties to customize the path. For example if you set `static_mountpoint` to `base-services-secrets` then the path
for the static environments would be:

  ```base-services-secrets/example-service/production/common/certificates/example-service.example.com```

See the list of properties bellow.

#### General properties

  - `certificate_common_name` - CN of the certificate. No default, this must be specified.
  - `environment` - the environment on which the node is being provisioned. Default: the chef environment.
  - `static_environments` - an array of regexes used to compute whether the node is being provisioned in a static or dynamic environment.
                            If `environment` matches any of the regexes then `static_path` will be used. Otherwise `dynamic_path` will be used.
                            Default: `[/production/, /staging/]`.

#### Vault properties

  - `address` - the address of the Vault Server. Default: `http://127.0.0.1:8200`.
  - `token` - the token used to authenticate against the Vault Server. No default, this must be specified.

#### Static environment properties
  
  - `static_mountpoint` - the Vault mountpoint used for static environments. Default: `secret`
  - `service_name` - the name of the service being provisioned. No default, this must be specified on static environments.
  - `version` - the specific version of the service that is being provisioned. Only used when `use_common_path` is false. Default: empty string.
  - `common_path` - the path to use in `static_path` when `use_common_path` is set to true. Default: `common`.
  - `use_common_path` - whether to use `common_path` in `static_path`. Default: `true`.
  - `certificates_path` - the last path to use in `static_path`. This allows having multiple certificates for a single service. Default: `certificates`.
  - `static_path` - the full path used to get the certificate from Vault in a static environments. Default: using the defaults it would be
                    'secret/example-service/#{node.environment}/common/certificates/#{certificate_common_name}'

#### Dynamic environment properties
                    
  - `dynamic_mountpoint` - the Vault mountpoint used for dynamic environments. Default: 'pki/issue'.
  - `pki_role` - the role used in Vault pki to generate new certificates. No default, this must be specified on dynamic environments.
  - `dynamic_path` - the full path used to get the certificate from Vault in a dynamic environment. Default: using the defaults it would be
                     'pki/issue/#{pki_role}'
  - `dynamic_options` - the options to pass to the pki Vault backend. Default: `{ common_name: "#{certificate_common_name}" }`.

#### Certificate bundles properties

  - `combine_certificate_and_chain` - whether to combine the certificate and the CA trust chain in a single file in that order. Useful to use in Nginx. Default: `false`.
  - `combine_all` - whether to combine the certificate, the CA trust chain, and the private key in a single file in that order. Useful to use in HAProxy. Default: `false`.

#### Filesystem properties

  - `ssl_path` - directory where the certificates, chains, and keys will be stored. The final path might be different depending on `create_subfolders`.
                 The default is SO dependent, see [attributes](attributes/defaults.rb) for the final value.
  - `create_subfolders` - whether to create 'certs' and 'private' sub-folders inside `ssl_path`.
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