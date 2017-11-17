vault_certificate 'test-with-version.example.com' do
  service_name 'example-service'
  version 'v1-2017-11-05'
  use_common_path false
end

vault_certificate 'test-common.example.com' do
  service_name 'example-service'
end