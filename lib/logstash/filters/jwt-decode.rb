# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
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
  #    "extract_fields" => {"user_id" => "user.id"}
  # }    
  #   
  # 
  #
  config_name "jwt-decode"

  # Looks for a match in message which contains the token field
  config :match, :validate => :string
  # Valid algorithms are defined here https://tools.ietf.org/html/rfc7518#section-3.1
  config :signature_alg, :validate => :string, :default => "HS256"
  config :key, :validate => :string, :default => nil
  config :extract_fields, :validate => :hash


  public
  def register
    # Add instance variables
    if @key && !@signature_alg
      raise LogStash::ConfigurationError, "signature_alg has to be specified if key is present "
    end  
  end # def register

  public
  def filter(event)
    if not @key
      decoded_token = JWT.decode event.get(@match), nil, false
    else
      decoded_token = JWT.decode event.get(@match), @key, true, {algorithm: @signature_alg}    
    end

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
