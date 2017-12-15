node.normal['vault_certificate']['service_name'] = 'example-service'

vault_certificate 'test-with-version.example.com' do
  service_version 'v1-2017-11-05'
  use_common_path false
end

cert = vault_certificate 'test-common.example.com'

Chef::Log.warn(cert.certificate.to_s)
Chef::Log.warn(cert.chain.to_s)
Chef::Log.warn(cert.key.to_s)

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
