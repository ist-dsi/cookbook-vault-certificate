resource_name :vault_certificate

require 'vault'

# TODO: it would be nice to support PCKS11

default_action :create

property :certificate_common_name, String, name_property: true, required: true
property :service_name, String, default: lazy { node['vault_certificate']['service_name'] }, required: true, callbacks: {
  'service_name cannot be empty' => ->(p) { !p.empty? },
}
property :environment, String, default: lazy { node['vault_certificate']['environment'] }, required: true
property :version, String, default: lazy { node['vault_certificate']['version'] }, required: true

# The address of the Vault Server.
property :address, String, default: lazy { node['vault_certificate']['address'] }, required: true
# The token used to authenticate against the Vault Server
property :token, String, default: lazy { node['vault_certificate']['token'] }, required: true

# The list of environments for which the static path will be used to retrieve the Certificate from Vault.
# This is an array of regexes. If any regex matches then the static path will be used.
property :static_environments, Array, default: lazy { node['vault_certificate']['static_environments'] }

# The Vault mountpoint used for static environments. By default 'secret'.
property :static_mountpoint, String, default: lazy { node['vault_certificate']['static_mountpoint'] }, required: true
# The path to use in :static_path when :use_common_path is set to true. By default 'common'.
property :common_path, String, default: lazy { node['vault_certificate']['common_path'] }, required: true
# Whether to use :common_path in :static_path. By default true.
# If true the :static_path by default would be:
#   "secret/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
# Otherwise
#   "secret/#{service_name}/#{environment}/#{version}/certificates/#{certificate_common_name}"
property :use_common_path, equal_to: [true, false], default: lazy { node['vault_certificate']['use_common_path'] }, required: true
# The last path to use in :static_path. By default 'certificates'.
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
# The options to pass to the pki Vault backend.
property :dynamic_options, Hash, default: lazy {
  { common_name: certificate_common_name }
}, required: true

# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [TrueClass, FalseClass], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [TrueClass, FalseClass], default: false

# The top-level directory in the filesystem where the certificates, chains, and keys will be stored. The default value is SO dependent.
# If create_subfolders is true then
#   certificates and chains will be created inside #{certificate_path}/certs
#   private keys will be created inside #{certificate_path}/private
# Otherwise
#   certificates, chains and private keys will be created directly inside certificate_path.
property :ssl_path, String, default: lazy { node['vault_certificate']['ssl_path'] }, required: true

# Whether to create 'certs' and 'private' sub-folders inside `certificate_path`. The default value is SO dependent.
property :create_subfolders, [TrueClass, FalseClass], default: lazy { node['vault_certificate']['create_subfolders'] }, required: true

# The filename the managed certificate will have on the filesystem. By default "#{certificate_common_name}.pem"
property :certificate_filename, String, default: lazy { "#{certificate_common_name}.pem" }
# The filename the managed CA chain bundle will have on the filesystem. By default "#{certificate_common_name}-bundle.crt"
property :chain_filename, String, default: lazy { "#{certificate_common_name}-bundle.crt" }
# The filename the managed private key will have on the filesystem. By default "#{certificate_common_name}.key"
property :key_filename, String, default: lazy { "#{certificate_common_name}.key" }

# The owner of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :owner, String, default: lazy { node['vault_certificate']['owner'] }, required: true
# The group of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :group, String, default: lazy { node['vault_certificate']['group'] }, required: true

# Accesors for determining where files should be placed
def certificate
  bits = [ssl_path, certificate_filename]
  bits.insert(1, 'certs') if create_subfolders
  ::File.join(bits)
end

def chain
  bits = [ssl_path, chain_filename]
  bits.insert(1, 'certs') if create_subfolders
  ::File.join(bits)
end

def key
  bits = [ssl_path, key_filename]
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
    if new_resource.static_environments.count { |r| r.match(new_resource.environment) } > 0
      Chef::Log.debug("vault-certificate: in a static environment. Static Path: '#{new_resource.static_path}'")
      result = vault_client.logical.read(new_resource.static_path)
      Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.static_path}'") if result.nil?
    else
      Chef::Log.debug("vault-certificate: in a dynamic environment. Dynamic Path: '#{new_resource.dynamic_path}'. Dynamic Options: #{new_resource.dynamic_options}")
      result = vault_client.logical.write(new_resource.dynamic_path, new_resource.dynamic_options)
      Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.dynamic_path}' and options #{new_resource.dynamic_options}") if result.nil?
    end
    {
      certificate: result.data[:certificate],
      chain: result.data[:ca_chain].nil? ? result.data[:issuing_ca] : result.data[:ca_chain].join('\n'),
      private_key: result.data[:private_key],
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
