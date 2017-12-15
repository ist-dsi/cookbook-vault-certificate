resource_name :vault_certificate

require 'vault'
require 'openssl'

default_action :create

# ======================================================================================================================
# == General properties ================================================================================================
# ======================================================================================================================
# CN of the certificate.
property :certificate_common_name, String, name_property: true, required: true
# The environment on which the node is being provisioned.
property :environment, String, default: lazy { node['vault_certificate']['environment'] }, required: true
# An array of regexes used to compute whether the node is being provisioned in a static or dynamic environment.
# If `environment` matches any of the regexes then `static_path` will be used. Otherwise `dynamic_path` will be used.
property :static_environments, Array, default: lazy { node['vault_certificate']['static_environments'] }

# ======================================================================================================================
# == Vault properties ==================================================================================================
# ======================================================================================================================
# The address of the Vault Server.
property :address, String, default: lazy { node['vault_certificate']['address'] }
# The token used to authenticate against the Vault Server
property :token, String, default: lazy { node['vault_certificate']['token'] }

# ======================================================================================================================
# == Static environment properties =====================================================================================
# ======================================================================================================================
# The Vault mountpoint used for static environments. By default 'secret'.
property :static_mountpoint, String, default: lazy { node['vault_certificate']['static_mountpoint'] }, required: true
# The name of the service being provisioned.
property :service_name, String, default: lazy { node['vault_certificate']['service_name'] }, required: true
# The specific version of the service that is being provisioned. Only used when `use_common_path` is false.
property :service_version, String, default: lazy { node['vault_certificate']['service_version'] }, required: true
# The path to use in :static_path when :use_common_path is set to true. By default 'common'.
property :common_path, String, default: lazy { node['vault_certificate']['common_path'] }, required: true
# Whether to use :common_path in :static_path. By default true.
# If true the :static_path by default would be:
#   "secret/#{service_name}/#{environment}/common/certificates/#{certificate_common_name}"
# Otherwise
#   "secret/#{service_name}/#{environment}/#{service_version}/certificates/#{certificate_common_name}"
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
    Chef::Application.fatal!("When use_common_path is false, service_version must be specified! Got service_version = '#{service_version}'.") if service_version.empty?
    "#{start}/#{service_version}/#{finish}"
  end
}, required: true

# ======================================================================================================================
# == Dynamic environment properties ====================================================================================
# ======================================================================================================================
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

# ======================================================================================================================
# == Certificate bundles properties ====================================================================================
# ======================================================================================================================
# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [TrueClass, FalseClass], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [TrueClass, FalseClass], default: false

# ======================================================================================================================
# == Stores (PKCS12 and Java) properties ===============================================================================
# ======================================================================================================================
# The top-level directory where stores will be created.
property :store_path, String
# The password used to protected the store.
property :store_password, String

# The password used to encrypt the key inside the store.
# If not set, set to nil or set to empty string the key will not be encrypted.
property :key_encryption_password, String
# The cipher used to encrypt the key.
property :key_encryption_cipher, String, default: lazy { node['vault_certificate']['key_encryption_cipher'] }

# The password for the keystore. By default the same as store_password.
# Having a separate property for the keystore password allows having different passwords for the
# keystore and the truststore when using the action create_key_and_trust_stores.
property :keystore_password, String, default: lazy { store_password }
# The filename the keystore will have on the filesystem. By default "#{certificate_common_name}.keystore.jks".
property :keystore_filename, String, default: lazy { "#{certificate_common_name}.keystore.jks" }
# The password for the truststore. By default the same as store_password.
# Having a separate property for the truststore password allows having different passwords for the
# keystore and the truststore when using the action create_key_and_trust_stores.
property :truststore_password, String, default: lazy { store_password }
# The filename the truststore will have on the filesystem. By default "#{certificate_common_name}.truststore.jks".
property :truststore_filename, String, default: lazy { "#{certificate_common_name}.truststore.jks" }

# The filename the pkcs12 store will have on the filesystem. By default "#{certificate_common_name}.pkcs12".
property :pkcs12store_filename, String, default: lazy { "#{certificate_common_name}.pkcs12" }
# ======================================================================================================================
# == Filesystem properties =============================================================================================
# ======================================================================================================================
# The top-level directory in the filesystem where the certificates, chains, and keys will be created. The default value is SO dependent.
# If create_subfolders is true then
#   certificates and chains will be created inside #{certificate_path}/certs
#   private keys will be created inside #{certificate_path}/private
# Otherwise
#   certificates, chains and private keys will be created directly inside certificate_path.
property :ssl_path, String, default: lazy { node['vault_certificate']['ssl_path'] }, required: true
# Whether to create 'certs' and 'private' sub-folders inside `certificate_path`. The default value is SO dependent.
property :create_subfolders, [TrueClass, FalseClass], default: lazy { node['vault_certificate']['create_subfolders'] }, required: true
# The filename the managed certificate will have on the filesystem. By default "#{certificate_common_name}.pem".
property :certificate_filename, String, default: lazy { "#{certificate_common_name}.pem" }
# The filename the managed CA chain bundle will have on the filesystem. By default "#{certificate_common_name}-bundle.crt".
property :chain_filename, String, default: lazy { "#{certificate_common_name}-bundle.crt" }
# The filename the managed private key will have on the filesystem. By default "#{certificate_common_name}.key".
property :key_filename, String, default: lazy { "#{certificate_common_name}.key" }
# The owner of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :owner, String, default: lazy { node['vault_certificate']['owner'] }, required: true
# The group of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :group, String, default: lazy { node['vault_certificate']['group'] }, required: true

# ======================================================================================================================
# == Accesors ==========================================================================================================
# ======================================================================================================================
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

def pkcs12store
  ::File.join([store_path, pkcs12store_filename])
end

def keystore
  ::File.join([store_path, keystore_filename])
end

def truststore
  ::File.join([store_path, truststore_filename])
end

# ======================================================================================================================
# == Shared methods ====================================================================================================
# ======================================================================================================================
action_class do
  def cert_directory_resource(dir, private = false)
    directory ::File.join(new_resource.ssl_path, dir) do
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

  def fetch_certs_from_vault
    ssl_item = begin
      Vault.address = new_resource.address unless new_resource.address.nil?
      Vault.token = new_resource.token unless new_resource.token.nil?
      if new_resource.static_environments.count { |r| r.match(new_resource.environment) } > 0
        Chef::Log.debug("vault-certificate: in a static environment. Static Path: '#{new_resource.static_path}'")
        result = Vault.logical.read(new_resource.static_path)
        Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.static_path}'") if result.nil?
      else
        Chef::Log.debug("vault-certificate: in a dynamic environment. Dynamic Path: '#{new_resource.dynamic_path}'. Dynamic Options: #{new_resource.dynamic_options}")
        result = Vault.logical.write(new_resource.dynamic_path, new_resource.dynamic_options)
        Chef::Application.fatal!("Vault (#{new_resource.address}) returned nil for path '#{new_resource.dynamic_path}' and options #{new_resource.dynamic_options}") if result.nil?
      end
      result.data
    rescue => e
      Chef::Application.fatal!(e.message)
    end

    Chef::Application.fatal!('Could not get certificate from Vault') if ssl_item[:certificate].nil?
    Chef::Application.fatal!('Could not get chain from Vault') if ssl_item[:ca_chain].nil? && ssl_item[:issuing_ca].nil?
    Chef::Application.fatal!('Could not get private_key from Vault') if ssl_item[:private_key].nil?
    ssl_item
  end

  def generate_pkcs12_store_der(ssl_item = fetch_certs_from_vault, pass = nil)
    Chef::Log.warn('store_password is nil. The PKCS12 store will have as password the empty string!') if new_resource.store_password.nil? && pass.nil?
    # TODO: if the key is already encrypted this will fail
    key = OpenSSL::PKey.read(ssl_item[:private_key])
    if encrypt_key?
      cipher = OpenSSL::Cipher.new(new_resource.key_encryption_cipher)
      # This is stupid, we are encrypting the key only to decrypt it later when we parse it back to a PKey
      # However this seems to be the correct way to do it.
      encrypted_key = key.to_pem(cipher, new_resource.key_encryption_password)
      key = OpenSSL::PKey.read(encrypted_key, new_resource.key_encryption_password)
    end

    crt = OpenSSL::X509::Certificate.new(ssl_item[:certificate])

    chain = [crt]
    if ssl_item[:ca_chain].nil?
      chain = chain.push(OpenSSL::X509::Certificate.new(ssl_item[:issuing_ca]))
    else
      chain += ssl_item[:ca_chain].map { |item| OpenSSL::X509::Certificate.new(item) }
    end

    store_pass = if !pass.nil?
                   pass
                 else
                   new_resource.store_password
                 end
    pkcs12_store = OpenSSL::PKCS12.create(store_pass, new_resource.certificate_common_name, key, crt, chain)
    pkcs12_store.to_der
  end

  def ensure_keytool_is_installed
    Mixlib::ShellOut.new('keytool').run_command
  rescue
    Chef::Application.fatal!('Keytool is not installed. Cannot generate Java key/trust stores!')
  end

  def encrypt_key?
    property_is_set?(:key_encryption_password) && !new_resource.key_encryption_password.nil? && !new_resource.key_encryption_password.empty?
  end

  def alias_exists_in_store?(keystore, storepass, store_alias)
    cmd = Mixlib::ShellOut.new("keytool -keystore #{keystore} -storepass #{storepass} -list -alias #{store_alias}")
    cmd.run_command.status == 0
  end

  def delete_alias(keystore, storepass, store_alias)
    cmd = Mixlib::ShellOut.new("keytool -keystore #{keystore} -storepass #{storepass} -delete -alias #{store_alias}")
    cmd.run_command
  end

  def already_in_store?(keystore, storepass, store_alias, content)
    cmd = Mixlib::ShellOut.new("keytool -keystore #{keystore} -storepass #{storepass} -list -rfc -alias #{store_alias} | tail -n+5")
    cmd.run_command
    result = cmd.stdout.chomp
    if cmd.exitstatus == 0 && !result.empty?
      # TODO: will this work if there are multiple certificates in the store?
      cert_in_store = OpenSSL::X509::Certificate.new(result)
      expected_cert = OpenSSL::X509::Certificate.new(content)
      # Isn't this great comparing certificates by their to string implementation
      # when this - https://github.com/ruby/openssl/issues/158 - is released (in version 2.1.0) we can do the proper implementation
      cert_in_store.to_pem.eql? expected_cert.to_pem
    else
      false
    end
  end

  def create_keystore(ssl_item = fetch_certs_from_vault)
    ensure_keytool_is_installed

    Chef::Application.fatal!('store_path is nil while trying to generate a Java keystore') if new_resource.store_path.nil?
    if new_resource.keystore_password.nil? || new_resource.keystore_password.length < 6
      Chef::Application.fatal!('keystore_password must be defined and have at least 6 characters.')
    end
    require 'tempfile'
    tempfile = Tempfile.new("#{new_resource.certificate_common_name}.pkcs12")
    begin
      # We need to ensure the pkcs12 store has a password that is not the empty string. So we override the pass to be keystore password
      tempfile.write(generate_pkcs12_store_der(ssl_item, new_resource.keystore_password))
      tempfile.close

      command_string = 'keytool -importkeystore -noprompt'
      command_string += " -srckeystore #{tempfile.path} -destkeystore #{keystore} -srcstoretype PKCS12"
      command_string += " -srcstorepass #{new_resource.keystore_password} -deststorepass #{new_resource.keystore_password}"
      command_string += " -srcalias #{new_resource.certificate_common_name}"
      command_string += " -srckeypass #{new_resource.key_encryption_password} -destkeypass #{new_resource.key_encryption_password}" if encrypt_key?

      keytool = Mixlib::ShellOut.new(command_string)
      keytool.run_command
      unless keytool.exitstatus == 0
        Chef::Application.fatal!("Failed to create keystore! #{keytool.stdout}\n\n#{keytool.stderr}")
      end

      file keystore do
        owner new_resource.owner
        group new_resource.group
      end
    ensure
      tempfile.unlink # deletes the temp file
    end
  end

  def create_truststore(ssl_item = fetch_certs_from_vault)
    ensure_keytool_is_installed

    Chef::Application.fatal!('store_path is nil while trying to generate a Java truststore.') if new_resource.store_path.nil?
    if new_resource.truststore_password.nil? || new_resource.truststore_password.length < 6
      Chef::Application.fatal!('truststore_password must be defined and have at least 6 characters.')
    end

    chain_certs = ssl_item[:ca_chain].nil? ? ssl_item[:issuing_ca] : ssl_item[:ca_chain].join('\n')
    store_alias = new_resource.certificate_common_name
    if already_in_store?(truststore, new_resource.truststore_password, store_alias, chain_certs)
      # The truststore already exists and has its content up to date. Have have to do nothing
      # We have the "if already_in_store(...) else ... end" instead of "unless already_in_store(...) ... end"
      # because with the unless the cookstyle would wrongly complain
    else
      if alias_exists_in_store?(truststore, new_resource.truststore_password, store_alias)
        # The store already has the alias so we need to remove it first
        delete_alias(truststore, new_resource.truststore_password, store_alias)
      end
      command_string = "keytool -importcert -alias #{store_alias}"
      command_string += " -noprompt -keystore #{truststore} -storepass #{new_resource.truststore_password}"

      keytool = Mixlib::ShellOut.new(command_string)
      keytool.input = chain_certs
      keytool.run_command
      unless keytool.exitstatus == 0
        Chef::Application.fatal!("Failed to create keystore! #{keytool.stdout}\n\n#{keytool.stderr}")
      end

      file truststore do
        owner new_resource.owner
        group new_resource.group
      end
    end
  end
end

# ======================================================================================================================
# == Implementation ====================================================================================================
# ======================================================================================================================
action :create do
  ssl_item = fetch_certs_from_vault

  if new_resource.create_subfolders
    cert_directory_resource 'certs'
    cert_directory_resource 'private', true
  end

  chain_certs = ssl_item[:ca_chain].nil? ? ssl_item[:issuing_ca] : ssl_item[:ca_chain].join('\n')
  if new_resource.combine_all
    certificate_file_resource certificate,
                       "#{ssl_item[:certificate]}\n#{chain_certs}\n#{ssl_item[:private_key]}",
                       true
  else
    if new_resource.combine_certificate_and_chain
      certificate_file_resource certificate, "#{ssl_item[:certificate]}\n#{chain_certs}"
    else
      certificate_file_resource certificate, ssl_item[:certificate]
      certificate_file_resource chain, chain_certs
    end
    certificate_file_resource key, ssl_item[:private_key], true
  end
end

action :create_pkcs12_store do
  Chef::Application.fatal!('store_path is nil while trying to generate a PKCS12 store') if new_resource.store_path.nil?
  file pkcs12store do
    content generate_pkcs12_store_der
    owner new_resource.owner
    group new_resource.group
  end
end

action :create_keystore do
  create_keystore
end

action :create_truststore do
  create_truststore
end

action :create_key_and_trust_stores do
  ssl_item = fetch_certs_from_vault
  create_truststore(ssl_item)
  create_keystore(ssl_item)
end
