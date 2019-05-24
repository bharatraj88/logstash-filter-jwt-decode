# encoding: utf-8
require "logstash/filters/base"
require "jwt"

# This  filter will decode the jwt token in your message event and retrievs the values
# as specified in `extract_fields` and adds the extracted values to the event.
#
# It is only intended to be used as an .
class LogStash::Filters::JWTDecode < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # jwt-decode {
  #    "match" => "token",
  #    "extract_fields" => {"business_id" => "user.busId"}
  # }    
  #   
  # 
  #
  config_name "jwt-decode"

  # Looks for a match in message which contains the token field
  config :match, :validate => :string, :required => true
  # Supported Algorithms NONE, HMAC, RSASSA and ECDSA
  config :signature_alg, :validate => :string, :required => false, :default => "NONE"
  config :key, :validate => :string, :required => false, :default => nil
  config :extract_fields, :validate => :hash, :required => true


  public
  def register
    # Add instance variables
    if not ['NONE', 'HMAC', 'RSASSA', 'ECDSA'].include? @signature_alg
      raise LogStash::ConfigurationError, "JWTDecode plugin: Invalid signature_alg '#{@signature_alg}' must be one of NONE, HMAC, RSASSA and ECDSA"
    end  
  end # def register

  public
  def filter(event)
    decoded_token = JWT.decode event.get(@match), @key, false, {algorithm: @signature_alg}    
    @extract_fields.each do |k, v| 
      event.set(k , getValueFromDecodedToken(v, decoded_token[0]))
    end
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  private
  def getValueFromDecodedToken(key, decoded_token)
    key.split(".").each do |val, index| 
          if decoded_token.nil?
            return nil 
          end 
          decoded_token = decoded_token[val]
    end
    return decoded_token;   
  end
end # class LogStash::Filters::JWTDecode
