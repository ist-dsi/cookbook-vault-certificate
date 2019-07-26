name 'vault-certificate'

maintainer 'Simão Martins'
maintainer_email 'simao.martins@tecnico.ulisboa.pt'

issues_url 'https://github.com/ist-dsi/cookbook-vault-certificate/issues'
source_url 'https://github.com/ist-dsi/cookbook-vault-certificate'

license 'Apache-2.0'

description 'Installs/Configures certificates, private keys, CA root bundles from Hashicorp Vault.'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))

version '1.1.3'
chef_version '>= 14.10'

%w( centos debian ubuntu ).each do |os|
  supports os
end

provides 'vault_certificate'

gem 'vault', '~> 0.12.0'
# We need 2.1.0 to be able to compare certificates with == instead of using to string.
gem 'openssl', '>= 2.1.0'
