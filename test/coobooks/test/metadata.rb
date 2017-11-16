name 'test'

maintainer 'Simão Martins'
maintainer_email 'simao.martins@tecnico.ulisboa.pt'

issues_url 'https://github.com/ist-dsi/cookbook-vault-certificate/issues'
source_url 'https://github.com/ist-dsi/cookbook-vault-certificate'

license 'Apache-2.0'

version '1.0.0'

%w( centos debian ).each do |os|
  supports os
end

chef_version '>= 12.8'

depends 'vault_certificate'
