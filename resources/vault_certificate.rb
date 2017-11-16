resource_name :vault_certificate

require 'vault'
# require 'openssl'

default_action :create

property :service_name, String, required: true
property :environment, String, default: node.chef_environment, required: true
property :version, String, required: true
property :certificate_common_name, String, name_property: true, required: true

# The address of the Vault Server,
property :address, String, default: node['vault_certificate']['address'], required: true
# The token used to authenticate against the Vault Server
property :token, String, default: node['vault_certificate']['token'], required: true

# The list of environments for which the static path will be used to retrieve the Certificate from Vault.
# This is an array of regexes. If any regex matches then the static path will be used.
property :static_environments, Array, default: node['vault_certificate']['static_environments']

# The Vault mountpoint used for static environments. By default 'secret',
property :static_mountpoint, String, default: node['vault_certificate']['static_mountpoint'], required: true
# The path to use in :static_path when :use_common_path is set to true. By default 'common'.
property :common_path, String, default: node['vault_certificate']['common_path'], required: true
# Whether to use :common_path in :static_path.
# If true the :static_path by default would be:
#   "secret/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
# Otherwise
#   "secret/#{service_name}/#{environment}/#{version}/certificates/#{certificate_common_name}"
property :use_common_path, equal_to: [true, false], default: node['vault_certificate']['use_common_path'], required: true
# The last path to use in :static_path. By default 'certificates'.
# TODO: find a better name for this property or for the certificate_path
property :certificates_path, String, default: node['vault_certificate']['certificates_path'], required: true
# The full path used, in a static environment, to get the certificate from Vault.
# By default "secrets/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
property :static_path, String, default: lazy {
  start = "#{static_mountpoint}/#{service_name}/#{new_resource.environment}"
  finish = "#{certificates_path}/#{certificate_common_name}"
  if use_common_path
    "#{start}/#{common_path}/#{finish}"
  else
    "#{start}/#{new_resource.version}/#{finish}"
  end
}, required: true

# The Vault mountpoint used for dynamic environments. By default 'pki/issue'
property :dynamic_mountpoint, String, default: node['vault_certificate']['dynamic_mountpoint'], required: true
# The role used in vault pki to generate new certificates.
property :pki_role, String, default: lazy { node['vault_certificate']['pki_role'] }, required: true
# The full path used, in a dynamic environment, to get the certificate from Vault.
# By default "pki/issue common_name=#{certificate_common_name}"
property :dynamic_path, String, default: lazy {
  "#{dynamic_mountpoint}/#{pki_role} common_name=#{certificate_common_name}"
}, required: true

# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [TrueClass, FalseClass], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [TrueClass, FalseClass], default: false

# :certificate_file is the filename for the managed certificate.
property :certificate_filename, String, default: "#{node['fqdn']}.pem"
# :key_file is the filename for the managed key.
property :key_filename, String, default: "#{node['fqdn']}.key"
# :chain_file is the filename for the managed CA chain.
property :chain_filename, String, default: "#{node['hostname']}-bundle.crt"

# :certificate_path is the top-level directory for certs/keys.
# If create_subfolders is true then
#   certificates and chains will be created inside #{certificate_path}/certs
#   private keys will be created inside #{certificate_path}/private
# Otherwise
#   certificates, chains and private keys will be created directly inside certificate_path.
# TODO: find a better name for this property or for the certificates_path
property :certificate_path, String, required: true, default: case node['platform_family']
                                                               when 'rhel', 'fedora'
                                                                 '/etc/pki/tls'
                                                               when 'smartos'
                                                                 '/opt/local/etc/openssl'
                                                               when 'windows'
                                                                 Chef::Config[:file_cache_path]
                                                               else
                                                                 '/etc/ssl'
                                                             end

# :create_subfolders will automatically create 'certs' and 'private' sub-folders
property :create_subfolders, [TrueClass, FalseClass], default: case node['platform_family']
                                                                 when 'debian', 'rhel', 'fedora', 'smartos'
                                                                   true
                                                                 else
                                                                   false
                                                               end

# The owner and group of the subfolders, the certificate, the chain and the private key
property :owner, String, default: 'root'
property :group, String, default: 'root'

action_class do
  # Accesors for determining where files should be placed
  def certificate
    bits = [certificate_path, certificate_filename]
    bits.insert(1, 'certs') if create_subfolders
    ::File.join(bits)
  end

  def key
    bits = [certificate_path, key_filename]
    bits.insert(1, 'private') if create_subfolders
    ::File.join(bits)
  end

  def chain
    bits = [certificate_path, chain_filename]
    bits.insert(1, 'certs') if create_subfolders
    ::File.join(bits)
  end

  def cert_directory_resource(dir, private = false)
    directory ::File.join(new_resource.certificate_path, dir) do
      owner new_resource.owner
      group new_resource.group
      mode(private ? 00750 : 00755)
      recursive true
    end
  end

  def certificate_file_resource(path, contents, private = false)
    file path do
      owner new_resource.owner
      group new_resource.group
      mode(private ? 00640 : 00644)
      content contents
      sensitive private
    end
  end
end

action :create do
  ssl_item = begin
    vault_client = Vault::Client.new(address: new_resource.address, token: new_resource.token)
    if static_environments.count { |r| r.match(new_resource.environment) } > 0
      result = vault_client.logical.read(static_path)
      Chef::Log.debug("vault-certificate: in a static environment. Static Path: #{static_path}. Result: #{result}")
      result.data
    else
      # We need to massage .data to ensure it is a json object with the fields
      # ['cert'], ['chain'], ['key']
      result = vault_client.logical.read(dynamic_path)
      Chef::Log.debug("vault-certificate: in a dynamic environment. Dynamic Path: #{dynamic_path}. Result: #{result}")
      result.data
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
