resource_name :vault_certificate

require 'vault'
# require 'openssl'

use_inline_resources

default_action :create

property :service_name, String, required: true
property :environment, String, default: node.chef_environment, required: true
property :version, String, required: true
property :certificate_common_name, String, name_property: true, required: true

# The address of the Vault Server,
property :address, String, default: node['vault_certificate']['address'], required: true
# The token used to authenticate against the Vault Server
# property :token, String, default: node['vault_certificate']['token'], required: true
# Is putting the token in an attribute a good idea?
property :token, String, required: true

# The list of environments for which the static path will be used to retrieve the Certificate from Vault.
# This is an array of regexes. If any regex matches then the static path will be used.
property :static_environments, Array, default: node['vault_certificate']['static_environments']

# The Vault mountpoint used for static environments. By default 'secret',
property :vault_static_mountpoint, String, default: node['vault_certificate']['vault_static_mountpoint'], required: true

# The path to use in :vault_static_path when :use_common_path is set to true. By default 'common'.
property :vault_common_path, String, default: node['vault_certificate']['vault_common_path'], required: true
# Whether to use :vault_common_path in :vault_static_path.
# If true the :vault_static_path by default would be:
#   "secret/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
# Otherwise
#   "secret/#{service_name}/#{environment}/#{version}/certificates/#{certificate_common_name}"
property :use_common_path, equal_to: [true, false], default: node['vault_certificate']['use_common_path'], required: true
# The last path to use in :vault_static_path. By default 'certificates'.
property :vault_certificates_path, String, default: node['vault_certificate']['vault_certificates_path'], required: true

# The full path used, in a static environment, to get the certificate from Vault.
# By default "secrets/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
property :vault_static_path, String, default: lazy {
  start = "#{vault_static_mountpoint}/#{service_name}/#{new_resource.environment}"
  finish = "#{vault_certificates_path}/#{certificate_common_name}"
  if use_common_path
    "#{start}/#{vault_common_path}/#{finish}"
  else
    "#{start}/#{new_resource.version}/#{finish}"
  end
}, required: true

# The Vault mountpoint used for dynamic environments. By default 'pki/issue'
property :vault_dynamic_mountpoint, String, default: node['vault_certificate']['vault_dynamic_mountpoint'], required: true
# The role used in vault pki to generate new certificates.
property :vault_pki_role, String, default: lazy { node['vault_certificate']['vault_pki_role'] }, required: true

# The full path used, in a dynamic environment, to get the certificate from Vault.
# By default "pki/issue common_name=#{certificate_common_name}"
property :vault_dynamic_path, String, default: lazy {
  "#{vault_dynamic_mountpoint}/#{vault_pki_role} common_name=#{certificate_common_name}"
}, required: true

# :certificate_path is the top-level directory for certs/keys (certs and private sub-folders are where the files will be placed)
property :certificate_path, String, required: true, default: case node['platform_family']
                                                             when 'rhel', 'fedora'
                                                               '/etc/pki/tls'
                                                             when 'debian'
                                                               '/etc/ssl'
                                                             when 'smartos'
                                                               '/opt/local/etc/openssl'
                                                             else
                                                               '/etc/ssl'
                                                             end

# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [TrueClass, FalseClass], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [TrueClass, FalseClass], default: false

# :certificate_file is the filename for the managed certificate.
property :certificate_file, String, default: "#{node['fqdn']}.pem"
# :key_file is the filename for the managed key.
property :key_file, String, default: "#{node['fqdn']}.key"
# :chain_file is the filename for the managed CA chain.
property :chain_file, String, default: "#{node['hostname']}-bundle.crt"

# :create_subfolders will automatically create 'certs' and 'private' sub-folders
property :create_subfolders, [TrueClass, FalseClass], default: true

# The owner and group of the subfolders, the certificate, the chain and the private key
property :owner, String, default: 'root'
property :group, String, default: 'root'

action_class do
  # Accesors for determining where files should be placed
  def certificate
    bits = [certificate_path, certificate_file]
    bits.insert(1, 'certs') if create_subfolders
    ::File.join(bits)
  end

  def key
    bits = [certificate_path, key_file]
    bits.insert(1, 'private') if create_subfolders
    ::File.join(bits)
  end

  def chain
    bits = [certificate_path, chain_file]
    bits.insert(1, 'certs') if create_subfolders
    ::File.join(bits)
  end

  def cert_directory_resource(dir, private = false)
    directory ::File.join(new_resource.certificate_path, dir) do
      owner new_resource.owner
      group new_resource.group
      mode (private ? 00750 : 00755)
      recursive true
    end
  end

  def certificate_file_resource(path, contents, private = false)
    file path do
      owner new_resource.owner
      group new_resource.group
      mode (private ? 00640 : 00644)
      content contents
      sensitive private
    end
  end
end

action :create do
  ssl_item = begin
    vault_client = Vault::Client.new(address: new_resource.address, token: new_resource.token)
    if new_resource.static_environments.count { |r| r.match(new_resource.environment) } > 0
      vault_client.logical.read(new_resource.vault_static_path).data
    else
      # We need to massage .data to ensure it is a json object with the fields
      # ['cert'], ['chain'], ['key']
      vault_client.logical.read(new_resource.vault_dynamic_path).data
    end
  rescue => e
    Chef::Application.fatal!(e.message)
  end

  raise 'Could not get a certificate from Vault' if ssl_item.nil?

  if new_resource.create_subfolders
    cert_directory_resource 'certs'
    cert_directory_resource 'private', true
  end

  if new_resource.combine_all
    certificate_file_resource new_resource.certificate,
                       "#{ssl_item['cert']}\n#{ssl_item['chain']}\n#{ssl_item['key']}",
                       true
  else
    if new_resource.combine_certificate_and_chain
      certificate_file_resource new_resource.certificate, "#{ssl_item['cert']}\n#{ssl_item['chain']}"
    else
      certificate_file_resource new_resource.certificate, ssl_item['cert']
      certificate_file_resource new_resource.chain, ssl_item['chain']
    end
    certificate_file_resource new_resource.key, ssl_item['key'], true
  end
end
