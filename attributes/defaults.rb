default['vault_certificate'] = {
  # The environment on which the node is being provisioned.
  'environment' => node.chef_environment,
  # The list of environments for which the static path will be used to retrieve the Certificate from Vault.
  # This is an array of regexes. If any regex matches then the static path will be used.
  'static_environments' => [/production/, /staging/],
  # The service version
  'service_version' => '',
  # The Vault mountpoint used for static environments.
  'static_mountpoint' => 'secret',
  # The service name
  'service_name' => '',
  # The path to use in vault_static_path when use_common_path is set to true.
  'common_path' => 'common',
  # Whether to use vault_common_path in the path for static environments.
  'use_common_path' => true,
  # The cipher that will be used to encrypt the key when :encrypt_key is true.
  'key_encryption_cipher' => 'AES-256-CBC',
  # The last path to use in the path for static environments.
  'certificates_path' => 'certificates',
  # The Vault mountpoint used for dynamic environments.
  'dynamic_mountpoint' => 'pki/issue',
  # The pki role used for the path of dynamic environments.
  'pki_role' => nil,
  # The owner of the subfolders, the certificate, the chain and the private key
  'owner' => 'root',
  # The group of the subfolders, the certificate, the chain and the private key
  'group' => 'root',
}

default['vault_certificate']['ssl_path'] = case node['platform_family']
                                           when 'rhel', 'fedora'
                                             '/etc/pki/tls'
                                           when 'smartos'
                                             '/opt/local/etc/openssl'
                                           else
                                             '/etc/ssl'
                                           end

default['vault_certificate']['create_subfolders'] = case node['platform_family']
                                                    when 'debian', 'rhel', 'fedora', 'smartos'
                                                      true
                                                    else
                                                      false
                                                    end
