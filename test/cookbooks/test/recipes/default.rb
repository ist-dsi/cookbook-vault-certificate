node.normal['vault_certificate']['service_name'] = 'example-service'

vault_certificate 'test-with-version.example.com' do
  version 'v1-2017-11-05'
  use_common_path false
end

cert = vault_certificate 'test-common.example.com'

Chef::Log.warn(cert.certificate.to_s)
Chef::Log.warn(cert.chain.to_s)
Chef::Log.warn(cert.key.to_s)
