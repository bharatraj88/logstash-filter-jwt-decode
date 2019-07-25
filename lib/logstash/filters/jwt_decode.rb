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
  # jwt_decode {
  #    "match" => "token",
  #    "extract_fields" => {"user_id" => "user.id"}
  # }    
  #   
  # 
  #
  config_name "jwt_decode"

  # Looks for a match in message which contains the token field
  config :match, :validate => :string, :required => true
  # Valid algorithms are defined here https://tools.ietf.org/html/rfc7518#section-3.1
  config :signature_alg, :validate => :string, :required => false, :default => "HS256"
  config :key, :validate => :string, :required => false, :default => nil
  config :extract_fields, :validate => :hash, :required => true


  public
  def register
    # Add instance variables
    if @key && !@signature_alg
      raise LogStash::ConfigurationError, "signature_alg has to be specified if key is present "
    end  
  end # def register

  public
  def filter(event)
    begin 
      if not @key
        decoded_token = JWT.decode event.get(@match), nil, false
      else
        decoded_token = JWT.decode event.get(@match), @key, true, {algorithm: @signature_alg}    
      end

      @extract_fields.each do |k, v| 
        event.set(k , getValueFromDecodedToken(v, decoded_token[0]))
      end
    rescue JWT::ExpiredSignature
      event.set("JWT_PARSER_ERROR","ExpiredSignature")
    rescue JWT::ImmatureSignature
      event.set("JWT_PARSER_ERROR","ImmatureSignature")
    rescue JWT::InvalidIssuerError
      event.set("JWT_PARSER_ERROR","InvalidIssuerError")
    rescue JWT::InvalidAudError
      event.set("JWT_PARSER_ERROR","InvalidAudError")
    rescue JWT::InvalidJtiError
      event.set("JWT_PARSER_ERROR","InvalidJtiError")
    rescue JWT::InvalidIatError
      event.set("JWT_PARSER_ERROR","InvalidIatError")
    rescue JWT::InvalidSubError
      event.set("JWT_PARSER_ERROR","InvalidSubError")
    rescue JWT::JWKError
      event.set("JWT_PARSER_ERROR","JWKError")
    rescue JWT::DecodeError  
      event.set("JWT_PARSER_ERROR","DecodeError")
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
end # class LogStash::Filters::jwt_decode
