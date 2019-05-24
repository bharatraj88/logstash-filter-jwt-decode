# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/jwt-decode"

describe LogStash::Filters::JWTDecode do
  context "Check Decode token" do
    describe " registering filter with all params" do
      it "Get business from Token" do
        filter = setup_filter({
          "match" => "token",
          "extract_fields" => {"business_id" => "user.busId"}
        })
        event = start_event({"token" => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7InVzZXJuYW1lIjoidGVzdEB0dXJ2by5jb20iLCJjbGllbnRJZCI6Im1hZ2VsbGFuLXdzIiwiYnVzSWQiOjQsImJ1c05hbWUiOiJUZXN0IiwibG9naW5CeUlkIjo3LCJsb2dpbkJ5TmFtZSI6IlRlc3QgVXNlciAgICIsInVzZXJUaW1lem9uZSI6IkFtZXJpY2EvTG9zX0FuZ2VsZXMiLCJidXNUaW1lem9uZSI6IkFtZXJpY2EvTG9zX0FuZ2VsZXMiLCJ0eXBlIjoiQlVTVVNFUiIsImFkbWluIjpmYWxzZSwiZGV2aWNlSWQiOm51bGwsInNjb3BlIjoicmVhZCx3cml0ZSIsImF1dGhvcml6ZWRHcmFudFR5cGVzIjpudWxsLCJyZXNvdXJjZUlkcyI6InJlc291cmNlLWNvcmUifX0.3weaxgRD5qRTUaazA5DWO7t5WoAJB8jghDMjJF9mWew"})
        filter.filter(event)
        expect(event.get("business_id")).to eq(4)
      end
    end
  end
end