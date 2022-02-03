# unified_mode true

resource_name :vault_certificate
provides :vault_certificate

require 'vault'
require 'openssl'

default_action :create

# ======================================================================================================================
# == General properties ================================================================================================
# ======================================================================================================================
# CN of the certificate.
property :common_name, String, name_property: true
# The path in Vault from which to read or write the certificate
property :vault_path, String, required: true
# The options to pass Vault. If set the Vault operation will be a write otherwise a read.
property :options, Hash, default: lazy { node['vault_certificate']['options'] || { 'common_name' => common_name } }
# Whether to set the sensitive flag on the generated certificate. The key file is always generated with sensitive set to true
property :output_certificates, [true, false], default: true
# If set to true vault-certificate will always ask Vault for a certificate. Otherwise it will check whether the certificate
# and key exist in the file system and if the certificate is still valid. Only when the certificate is invalid (probably
# because it has expired) will vault certificate ask Vault for a certificate.
property :always_ask_vault, [true, false], default: lazy { node['vault_certificate']['always_ask_vault'] }
# Number of days to request a new certificate before the current one expires, default 0 days.
property :ask_vault_n_days_before_expiry, Integer, default: 30
# ======================================================================================================================
# == Certificate bundles properties ====================================================================================
# ======================================================================================================================
# If true .certificate will point to a PEM file which contains the certificate and the CA trust chain in that order.
property :combine_certificate_and_chain, [true, false], default: false
# If true .certificate will point to a PEM file which contains the certificate, the CA trust chain, and the private key in that order.
property :combine_all, [true, false], default: false

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
# The filename the keystore will have on the filesystem. By default "#{common_name}.keystore.jks".
property :keystore_filename, String, default: lazy { "#{common_name}.keystore.jks" }
# The password for the truststore. By default the same as store_password.
# Having a separate property for the truststore password allows having different passwords for the
# keystore and the truststore when using the action create_key_and_trust_stores.
property :truststore_password, String, default: lazy { store_password }
# The filename the truststore will have on the filesystem. By default "#{common_name}.truststore.jks".
property :truststore_filename, String, default: lazy { "#{common_name}.truststore.jks" }

# The filename the pkcs12 store will have on the filesystem. By default "#{common_name}.pkcs12".
property :pkcs12store_filename, String, default: lazy { "#{common_name}.pkcs12" }
# ======================================================================================================================
# == Filesystem properties =============================================================================================
# ======================================================================================================================
# The top-level directory in the filesystem where the certificates, chains, and keys will be created.
# If create_subfolders is true then
#   certificates and chains will be created inside #{certificate_path}/certs
#   private keys will be created inside #{certificate_path}/private
# Otherwise
#   certificates, chains and private keys will be created directly inside certificate_path.
property :ssl_path, String, default: lazy { node['vault_certificate']['ssl_path'] }
# Whether to create 'certs' and 'private' sub-folders inside `certificate_path`. The default value is SO dependent.
property :create_subfolders, [true, false], default: true
# The filename the managed certificate will have on the filesystem. By default "#{common_name}.pem".
property :certificate_filename, String, default: lazy { "#{common_name}.pem" }
# The filename the managed CA chain will have on the filesystem. By default "#{common_name}.chain.pem".
property :chain_filename, String, default: lazy { "#{common_name}.chain.pem" }
# The filename the managed private key will have on the filesystem. By default "#{common_name}.key".
property :key_filename, String, default: lazy { "#{common_name}.key" }
# The filename the managed bundle (certificate + chain + key?) will have on the filesystem. By default "#{common_name}.bundle.pem".
property :bundle_filename, String, default: lazy { "#{common_name}.bundle.pem" }
# The owner of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :owner, String, default: lazy { node['vault_certificate']['owner'] }
# The group of the subfolders, the certificate, the chain and the private key. By default 'root'.
property :group, String, default: lazy { node['vault_certificate']['group'] }

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

def bundle
  bits = [ssl_path, bundle_filename]
  bits.insert(1, 'certs') if create_subfolders && combine_certificate_and_chain
  bits.insert(1, 'private') if create_subfolders && combine_all
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
  def parse_bundle(content)
    content.split(/(?<=-----END CERTIFICATE-----)\n?/).map { |c| OpenSSL::X509::Certificate.new(c) }
  end

  def cert_directory_resource(dir, private = false)
    directory ::File.join(new_resource.ssl_path, dir) do
      owner new_resource.owner
      group new_resource.group
      mode(private ? 00750 : 00755)
      recursive true
    end
  end

  def certificate_file_resource(path, contents, sensitive = false)
    with_run_context :root do
      file path do
        owner new_resource.owner
        group new_resource.group
        mode(sensitive ? 00640 : 00644)
        content contents
        sensitive sensitive
      end
    end
  end

  def deep_copy(o)
    Marshal.load(Marshal.dump(o))
  end

  def x509_certificate
    cert_text = if new_resource.combine_all || new_resource.combine_certificate_and_chain
                  ::File.read(bundle).partition(/(?<=-----END CERTIFICATE-----\n)/).first
                else
                  ::File.read(certificate)
                end
    OpenSSL::X509::Certificate.new(cert_text)
  end

  def fetch_certs_from_vault
    result = if new_resource.options.empty?
               Chef::Log.info("[vault-certificate] without options, going to perform a read at #{new_resource.vault_path}")
               Vault.logical.read(new_resource.vault_path)
             else
               Chef::Log.info("[vault-certificate] with options = #{new_resource.options}, going to perform a write at #{new_resource.vault_path}")
               Vault.logical.write(new_resource.vault_path, new_resource.options)
             end
    raise ArgumentError, "[vault-certificate] Vault returned nil for path '#{new_resource.vault_path}' and options #{new_resource.options}" if result.nil?

    ssl_item = deep_copy(result.data)
    # The if makes it possible to read from KV version 2.
    ssl_item = ssl_item.key?(:data) ? ssl_item[:data] : ssl_item

    missing_items = []
    missing_items += ['certificate'] if ssl_item[:certificate].nil?
    missing_items += ['chain'] if ssl_item[:ca_chain].nil? && ssl_item[:issuing_ca].nil?
    missing_items += ['private_key'] if ssl_item[:private_key].nil?
    unless missing_items.empty?
      # This will probably log the private_key, should we ommit it?
      raise VaultCertificateError.new("[vault-certificate] Could not get #{missing_items.join(', ')} from Vault", ssl_item)
    end
    [:certificate, :issuing_ca, :private_key].each do |part|
      ssl_item[part] = ssl_item[part] + "\n" if ssl_item.key? part
    end
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

    store_pass = pass.nil? ? new_resource.store_password : pass
    pkcs12_store = OpenSSL::PKCS12.create(store_pass, new_resource.common_name, key, crt, chain)
    pkcs12_store.to_der
  end

  def ensure_keytool_is_installed
    Mixlib::ShellOut.new('keytool').run_command
  rescue
    raise 'Keytool is not installed. Cannot generate Java key/trust stores!'
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
      cert_in_store == expected_cert
    else
      false
    end
  end

  def create_keystore(ssl_item = fetch_certs_from_vault)
    ensure_keytool_is_installed

    raise 'store_path is nil while trying to generate a Java keystore' if new_resource.store_path.nil?
    if new_resource.keystore_password.nil? || new_resource.keystore_password.length < 6
      raise 'keystore_password must be defined and have at least 6 characters.'
    end
    require 'tempfile'
    tempfile = Tempfile.new("#{new_resource.common_name}.pkcs12")
    begin
      # We need to ensure the pkcs12 store has a password that is not the empty string. So we override the pass to be keystore password
      tempfile.write(generate_pkcs12_store_der(ssl_item, new_resource.keystore_password))
      tempfile.close

      command_string = 'keytool -importkeystore -noprompt'
      command_string += " -srckeystore #{tempfile.path} -destkeystore #{keystore} -srcstoretype PKCS12"
      command_string += " -srcstorepass #{new_resource.keystore_password} -deststorepass #{new_resource.keystore_password}"
      command_string += " -srcalias #{new_resource.common_name}"
      command_string += " -srckeypass #{new_resource.key_encryption_password} -destkeypass #{new_resource.key_encryption_password}" if encrypt_key?

      keytool = Mixlib::ShellOut.new(command_string)
      keytool.run_command
      unless keytool.exitstatus == 0
        raise "Failed to create keystore! #{keytool.stdout}\n\n#{keytool.stderr}"
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

    raise 'store_path is nil while trying to generate a Java truststore.' if new_resource.store_path.nil?
    if new_resource.truststore_password.nil? || new_resource.truststore_password.length < 6
      raise 'truststore_password must be defined and have at least 6 characters.'
    end

    chain_certs = ssl_item[:ca_chain].nil? ? ssl_item[:issuing_ca] : ssl_item[:ca_chain].join('\n')
    store_alias = new_resource.common_name
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
        raise "Failed to create keystore! #{keytool.stdout}\n\n#{keytool.stderr}"
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
  # TODO: look into https://docs.chef.io/custom_resources.html#converge-if-changed to see if we can implement this better
  # TODO: we should apply the same logic to the keystores
  if new_resource.always_ask_vault == false && ::File.file?(key) && ::File.file?(certificate)
    cert = x509_certificate
    name = cert.subject.to_a.select { |a| a.first == 'CN' }.first[1]
    if (cert.not_before < Time.now) && (cert.not_after > Time.now + new_resource.ask_vault_n_days_before_expiry * 24 * 3600) && (name == new_resource.common_name)
      Chef::Log.info('[vault-certificate] the certificate is still valid, not going to ask Vault for a new one')
      return
    end
  end

  ssl_item = fetch_certs_from_vault

  if new_resource.create_subfolders
    cert_directory_resource 'certs'
    cert_directory_resource 'private', true
  end

  chain_certs = ssl_item[:ca_chain].nil? ? ssl_item[:issuing_ca] : ssl_item[:ca_chain].join("\n")
  bundle_content = ssl_item[:certificate] + chain_certs + "\n"
  if new_resource.combine_certificate_and_chain
    certificate_file_resource(bundle, bundle_content, !new_resource.output_certificates)
  end
  if new_resource.combine_all
    certificate_file_resource(bundle, bundle_content + ssl_item[:private_key], true)
  end
  certificate_file_resource(certificate, ssl_item[:certificate], !new_resource.output_certificates)
  certificate_file_resource(chain, chain_certs, !new_resource.output_certificates)
  certificate_file_resource(key, ssl_item[:private_key], true)

end

action :revoke do
  if ::File.file?(certificate)
    serial = x509_certificate.serial.to_s(16).chars.each_slice(2).map { |a| a.join.downcase }.join(':')
    Vault.logical.write(new_resource.vault_path, serial_number: serial)
    [certificate, chain, key, bundle].each do |file|
      ::File.delete(file) if ::File.file? file
    end
  end
end

action :create_pkcs12_store do
  Chef::Application.fatal!('[vault-certificate] store_path is nil while trying to generate a PKCS12 store') if new_resource.store_path.nil?
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
