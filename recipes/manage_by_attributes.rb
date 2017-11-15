node['certificate'].each do |cert|
  cert.each_pair do |id, opts|
    Chef::Log.debug "Create certs #{id} from attribute"
    vault_certificate id do
      opts.each { |k, v| __send__(k, v) if respond_to?(k) } unless opts.nil?
    end
  end
end
