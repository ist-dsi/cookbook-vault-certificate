name 'vault-certificate'

maintainer 'Simão Martins'
maintainer_email 'simao.martins@tecnico.ulisboa.pt'

issues_url 'https://github.com/ist-dsi/cookbook-vault-certificate/issues'
source_url 'https://github.com/ist-dsi/cookbook-vault-certificate'

license 'Apache-2.0'

description 'Installs/Configures certificates, private keys, CA root bundles from Hashicorp Vault.'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version '0.4.0'
chef_version '>= 12.8' # We need 12.8 to be able to use gem in metadata.rb

%w( centos debian ubuntu fedora ).each do |os|
  supports os
end

provides 'vault_certificate'

gem 'vault'
