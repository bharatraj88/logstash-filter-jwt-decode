# encoding: utf-8
require "logstash/filters/base"
require "jwt"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::JwtFilter < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "jwt-filter"

  # Replace the message with this value.
  config :jwt_token_field, :validate => :string, :required => true
  # Supported Algorithms NONE, HMAC, RSASSA and ECDSA
  config :signature_alg, :validate => :string, :required => false, :default => "NONE"
  config :key, :validate => :string, :required => false, :default => nil
  config :extract_fields, :validate => :hash, :required => true


  public
  def register
    # Add instance variables
    if not ['NONE', 'HMAC', 'RSASSA', 'ECDSA'].include? @signature_alg
      raise LogStash::ConfigurationError, "JwtFilter plugin: Invalid signature_alg '#{@signature_alg}' must be one of NONE, HMAC, RSASSA and ECDSA"
    end  
  end # def register

  public
  def filter(event)

    decoded_token = JWT.decode event.get(@jwt_token_field), @key, true, {algorithm: @signature_alg}
    @extract_fields.each { |k, v| event[:k] = decoded_token[:v] }
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::JwtFilter
