node.normal['vault_certificate'] = {
  'address' => 'http://dev-vault:8200/',
  'token' => ENV['VAULT_ROOT_TOKEN'],
}

Chef::Log.info("Vault Root Token is #{node['vault_certificate']['token']}")

# service_name: 'test',
# version: 'v1-2017-11-05',
# certificate_common_name: 'test.example.com',
# vault_pki_role: 'example-dot-com',
# address: 'http://dev-vault:8200/',
# token: 'abcd-1234',
