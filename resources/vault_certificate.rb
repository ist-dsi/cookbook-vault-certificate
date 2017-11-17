resource_name :vault_certificate

require 'vault'
# require 'openssl'

default_action :create

property :service_name, String, default: lazy { node['vault_certificate']['service_name'] }, required: true, callbacks: {
  'service_name cannot be empty' => lambda {|p| !p.empty?}
}
property :environment, String, default: node.chef_environment, required: true
property :version, String, default: lazy { node['vault_certificate']['version'] }, required: true
property :certificate_common_name, String, name_property: true, required: true

# The address of the Vault Server,
property :address, String, default: lazy { node['vault_certificate']['address'] }, required: true
# The token used to authenticate against the Vault Server
property :token, String, default: lazy { node['vault_certificate']['token'] }, required: true

# The list of environments for which the static path will be used to retrieve the Certificate from Vault.
# This is an array of regexes. If any regex matches then the static path will be used.
property :static_environments, Array, default: lazy { node['vault_certificate']['static_environments'] }

# The Vault mountpoint used for static environments. By default 'secret',
property :static_mountpoint, String, default: lazy { node['vault_certificate']['static_mountpoint'] }, required: true
# The path to use in :static_path when :use_common_path is set to true. By default 'common'.
property :common_path, String, default: lazy { node['vault_certificate']['common_path'] }, required: true
# Whether to use :common_path in :static_path.
# If true the :static_path by default would be:
#   "secret/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
# Otherwise
#   "secret/#{service_name}/#{environment}/#{version}/certificates/#{certificate_common_name}"
property :use_common_path, equal_to: [true, false], default: lazy { node['vault_certificate']['use_common_path'] }, required: true
# The last path to use in :static_path. By default 'certificates'.
# TODO: find a better name for this property or for the certificate_path
property :certificates_path, String, default: lazy { node['vault_certificate']['certificates_path'] }, required: true
# The full path used, in a static environment, to get the certificate from Vault.
# By default "secrets/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
property :static_path, String, default: lazy {
  start = "#{static_mountpoint}/#{service_name}/#{environment}"
  finish = "#{certificates_path}/#{certificate_common_name}"
  if use_common_path
    "#{start}/#{common_path}/#{finish}"
  else
    Chef::Application.fatal!("When use_common_path is false, version must be specified! Got version = '#{version}'.") if version.empty?
    "#{start}/#{version}/#{finish}"
  end
}, required: true

# The Vault mountpoint used for dynamic environments. By default 'pki/issue'
property :dynamic_mountpoint, String, default: lazy { node['vault_certificate']['dynamic_mountpoint'] }, required: true
# The role used in vault pki to generate new certificates.
property :pki_role, String, default: lazy { node['vault_certificate']['pki_role'] }, required: true
# The full path used, in a dynamic environment, to get the certificate from Vault.
# By default "pki/issue"
property :dynamic_path, String, default: lazy {
  "#{dynamic_mountpoint}/#{pki_role}"
}, required: true
property :dynamic_options, Hash, default: lazy {
  { common_name: certificate_common_name }
}, required: true



# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [TrueClass, FalseClass], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [TrueClass, FalseClass], default: false

# :certificate_file is the filename for the managed certificate.
property :certificate_filename, String, default: lazy { "#{certificate_common_name}.pem" }
# :chain_file is the filename for the managed CA chain.
property :chain_filename, String, default: lazy { "#{certificate_common_name}-bundle.crt" }
# :key_file is the filename for the managed key.
property :key_filename, String, default: lazy { "#{certificate_common_name}.key" }

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


# Accesors for determining where files should be placed
def certificate
  bits = [certificate_path, certificate_filename]
  bits.insert(1, 'certs') if create_subfolders
  ::File.join(bits)
end

def chain
  bits = [certificate_path, chain_filename]
  bits.insert(1, 'certs') if create_subfolders
  ::File.join(bits)
end

def key
  bits = [certificate_path, key_filename]
  bits.insert(1, 'private') if create_subfolders
  ::File.join(bits)
end

action_class do
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
    data = if new_resource.static_environments.count { |r| r.match(new_resource.environment) } > 0
      Chef::Log.warn("vault-certificate: in a static environment. Static Path: '#{new_resource.static_path}'")
      result = vault_client.logical.read(new_resource.static_path)
      Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.static_path}'") if result.nil?
      result.data
    else
      Chef::Log.warn("vault-certificate: in a dynamic environment. Dynamic Path: '#{new_resource.dynamic_path}'. Dynamic Options: #{new_resource.dynamic_options}")
      result = vault_client.logical.write(new_resource.dynamic_path, new_resource.dynamic_options)
      Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.dynamic_path}' and options #{new_resource.dynamic_options}") if result.nil?
      result.data
    end
    {
        certificate: data[:certificate],
        chain: if data[:ca_chain].nil? then data[:issuing_ca] else data[:ca_chain].join('\n') end,
        private_key: data[:private_key]
    }
  rescue => e
    Chef::Application.fatal!(e.message)
  end

  Chef::Application.fatal!('Could not get certificate from Vault') if ssl_item[:certificate].nil?
  Chef::Application.fatal!('Could not get chain from Vault') if ssl_item[:chain].nil?
  Chef::Application.fatal!('Could not get private_key from Vault') if ssl_item[:private_key].nil?

  if new_resource.create_subfolders
    cert_directory_resource 'certs'
    cert_directory_resource 'private', true
  end

  if new_resource.combine_all
    certificate_file_resource certificate,
                       "#{ssl_item[:certificate]}\n#{ssl_item[:chain]}\n#{ssl_item[:private_key]}",
                       true
  else
    if new_resource.combine_certificate_and_chain
      certificate_file_resource certificate, "#{ssl_item[:certificate]}\n#{ssl_item[:chain]}"
    else
      certificate_file_resource certificate, ssl_item[:certificate]
      certificate_file_resource chain, ssl_item[:chain]
    end
    certificate_file_resource key, ssl_item[:private_key], true
  end
end
