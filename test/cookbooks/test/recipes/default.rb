# Needed to create the java stores
adoptopenjdk_install '11' do
  variant 'hotspot'
  url 'https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.8%2B10/OpenJDK11U-jdk_x64_linux_hotspot_11.0.8_10.tar.gz'
  checksum '6e4cead158037cb7747ca47416474d4f408c9126be5b96f9befd532e0a762b47'
end

Vault.address = 'http://dev-vault:8200/'
Vault.token = node['token']

cert = vault_certificate 'test-common.example.com' do
  vault_path 'pki/issue/my-role'
end

Chef::Log.warn(cert.certificate.to_s)
Chef::Log.warn(cert.chain.to_s)
Chef::Log.warn(cert.key.to_s)

vault_certificate 'test-common.example.com' do
  vault_path 'pki/issue/my-role'
end
# How to test we did not asked Vault for the certificate again

vault_certificate 'test-common.example.com' do
  vault_path 'pki/issue/my-role'
  store_path '/tmp'
  keystore_password 'keystore'
  truststore_password 'truststore'
  key_encryption_password 'password'
  action :create_key_and_trust_stores
end

vault_certificate 'test-common.example.com' do
  vault_path 'pki/issue/my-role'
  store_path '/tmp'
  store_password 'testing'
  action :create_pkcs12_store
end

vault_certificate 'test-common.example.com' do
  vault_path 'pki/revoke'
  action :revoke
end
