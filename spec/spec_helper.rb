# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/jwtdecode"

def event(data = {})
	LogStash::Event.new(data)
end

def start_event(data = {})
	event(data)
end

def setup_filter(config = {})
	filter = LogStash::Filters::JWTDecode.new(config)
	filter.register()
	return filter
end