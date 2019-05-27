# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/jwt-decode"
require "jwt"

describe LogStash::Filters::JWTDecode do

  context "Configuration Validations " do
    describe " No match field" do
      it "Expect LogStash::ConfigurationError" do
        expect{
        filter = setup_filter({
          "extract_fields" => {"business_id" => "user.busId"}
        })
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

    describe " No extract_fields" do
      it "Expect LogStash::ConfigurationError" do
        expect{
        filter = setup_filter({
          "match" => "token"
        })
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

     describe " No signature_alg defined for key" do
      it "Expect LogStash::ConfigurationError" do
        expect{
        filter = setup_filter({
          "match" => "token",
          "extract_fields" => {"name" => "user.name", "id" => "user.id"},
          "key" => "SECRET",
          "signature_alg"=> nil
        })
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

    describe " Invalid Key" do
      it "Expect JWT::VerificationError" do
        expect{
        filter = setup_filter({
          "match" => "token",
          "extract_fields" => {"name" => "user.name", "id" => "user.id"},
          "key" => "SECRET123",
          "signature_alg"=>"HS256"
        })
        event = start_event({"token" => "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7Im5hbWUiOiJ0ZXN0TmFtZSIsImlkIjo0fX0.5fs1Ghwm9rtN2GaB66bhTLbYrEAuBxh4s46uOyX6Zos"})
        filter.filter(event)
        }.to raise_error(JWT::VerificationError)
      end
    end

  end

  context "Check Decode token" do
    describe " Decode token with no key " do
      it "Decode token with no key" do
        filter = setup_filter({
          "match" => "token",
          "extract_fields" => {"name" => "user.name", "id" => "user.id"}
        })
        event = start_event({"token" => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJ0ZXN0TmFtZSIsImlkIjo0fX0.P_GRg4n5J7ka3SQKG308clou9OuyxLxAj6V7kb7NcQQ"})
        filter.filter(event)
        expect(event.get("id")).to eq(4)
        expect(event.get("name")).to eq("testName")
      end
    end

    describe " Decode token with key " do
      it "Decode token with no key" do
        filter = setup_filter({
          "match" => "token",
          "extract_fields" => {"name" => "user.name", "id" => "user.id"},
          "key" => "SECRET",
          "signature_alg"=>"HS256"
        })
        event = start_event({"token" => "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjp7Im5hbWUiOiJ0ZXN0TmFtZSIsImlkIjo0fX0.5fs1Ghwm9rtN2GaB66bhTLbYrEAuBxh4s46uOyX6Zos"})
        filter.filter(event)
        expect(event.get("id")).to eq(4)
        expect(event.get("name")).to eq("testName")
      end
    end

  end

end