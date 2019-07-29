Vault.address = 'http://dev-vault:8200/'
Vault.token = node['token']

cert = vault_certificate 'test-common.example.com'

Chef::Log.warn(cert.certificate.to_s)
Chef::Log.warn(cert.chain.to_s)
Chef::Log.warn(cert.key.to_s)

vault_certificate 'test-common.example.com'
# How to test we did not asked Vault for the certificate again

vault_certificate 'test-common.example.com' do
  store_path '/tmp'
  keystore_password 'keystore'
  truststore_password 'truststore'
  key_encryption_password 'password'
  action :create_key_and_trust_stores
end

vault_certificate 'test-common.example.com' do
  store_path '/tmp'
  store_password 'testing'
  action :create_pkcs12_store
end

vault_certificate 'test-common.example.com' do
  vault_path 'pki/revoke'
  action :revoke
end
