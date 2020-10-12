name 'vault-certificate'

maintainer 'Simão Martins'
maintainer_email 'simao.martins@tecnico.ulisboa.pt'

issues_url 'https://github.com/ist-dsi/cookbook-vault-certificate/issues'
source_url 'https://github.com/ist-dsi/cookbook-vault-certificate'

license 'Apache-2.0'

description 'Installs/Configures certificates, private keys, CA root bundles from Hashicorp Vault.'

version '1.3.0'
chef_version '>= 14.10'

%w( centos debian ubuntu fedora).each do |os|
  supports os
end

gem 'vault', '>= 0.15.0'
# We need the openssl to be at least 2.1.0 to be able to compare certificates with == instead of using to string.
# This is already true from chef client 14.1 onwards
