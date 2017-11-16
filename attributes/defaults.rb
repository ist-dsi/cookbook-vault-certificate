node.default['vault_certificate'] = {
  # The address of the Vault Server.
  'address' => 'http://127.0.0.1:8200',
  # 'token' has no default value on purpose!
  # The list of environments for which the static path will be used to retrieve the Certificate from Vault.
  # This is an array of regexes. If any regex matches then the static path will be used.
  'static_environments' => [/production/, /staging/],
  # The Vault mountpoint used for static environments.
  'static_mountpoint' => 'secret',
  # The path to use in vault_static_path when use_common_path is set to true.
  'common_path' => 'common',
  # Whether to use vault_common_path in the path for static environments.
  'use_common_path' => true,
  # The last path to use in the path for static environments.
  'certificates_path' => 'certificates',
  # The Vault mountpoint used for dynamic environments.
  'dynamic_mountpoint' => 'pki/issue',
  # The pki role used for the path of dynamic environments.
  'pki_role' => nil,
}
