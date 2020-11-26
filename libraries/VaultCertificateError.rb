class VaultCertificateError < ArgumentError
  attr_reader :data
  def initialize(message, data)
    @data = data
    super(message)
  end
end
