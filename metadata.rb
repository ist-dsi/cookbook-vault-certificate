name 'vault-certificate'

maintainer 'Simão Martins'
maintainer_email 'simao.martins@tecnico.ulisboa.pt'

issues_url 'https://github.com/ist-dsi/cookbook-vault-certificate/issues'
source_url 'https://github.com/ist-dsi/cookbook-vault-certificate'

license 'Apache-2.0'

description 'Installs/Configures certificates, private keys, CA root bundles from Hashicorp Vault.'

version '2.0.4'
chef_version '>= 16'

%w( centos debian ubuntu).each do |os|
  supports os
end

gem 'vault', '>= 0.15.0'
