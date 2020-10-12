default['vault_certificate'] = {
  # The cipher that will be used to encrypt the key when :key_encryption_password is set.
  'key_encryption_cipher' => 'AES-256-CBC',
  'always_ask_vault' => false,
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
