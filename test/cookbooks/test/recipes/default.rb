Chef::Log.warn("Vault Address is #{node['vault_certificate']['address']}")
Chef::Log.warn("Vault Root Token is #{node['vault_certificate']['token']}")

vault_certificate 'test.example.com' do
  service_name 'test'
  version 'v1-2017-11-05'  
end

# certificate_common_name: ,
# vault_pki_role: 'example-dot-com',
# address: 'http://dev-vault:8200/',
# token: 'abcd-1234',
