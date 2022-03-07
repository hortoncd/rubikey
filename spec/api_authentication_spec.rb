require 'spec_helper'

describe "ApiAuthentication" do
  using Rubikey::StringExtensions

  let(:api_id) { ENV['YUBICO_API_ID'] }
  let(:api_key) { ENV['YUBICO_API_KEY'] }
  let(:unique_passcode) { ENV['YUBICO_UNIQUE_PASSCODE'] }
  #let(:api_id) { LOCAL_ENV['api_id'] }
  #let(:api_key) { LOCAL_ENV['api_key'] }
  #let(:unique_passcode) { LOCAL_ENV['unique_passcode'] }

  context 'authenticates' do
    it "a never used OTP" do
      VCR.use_cassette('never_used_otp') do
        expect(SecureRandom).to receive(:hex).with(16).and_return("09f2b2f09afe9c1b2f79a5d9e6fdd42a")
        authentication = Rubikey::ApiAuthentication.new(api_id: api_id, api_key: api_key, unique_passcode: unique_passcode)
        expect(authentication.status).to eq('OK')
      end
    end

    it "repleyed OTP" do
      VCR.use_cassette('already_used_otp') do
        expect(SecureRandom).to receive(:hex).with(16).and_return("9f5c24c7cf2e7c68d4e6b58c16b2e2e8")
        authentication = Rubikey::ApiAuthentication.new(api_id: api_id, api_key: api_key, unique_passcode: unique_passcode)
        expect(authentication.status).to eq('REPLAYED_OTP')
      end
    end

    it "invalid OTP" do
      VCR.use_cassette('invalid_otp') do
        expect(SecureRandom).to receive(:hex).with(16).and_return("46efa5aaebe517048085cd74c008a812")
        authentication = Rubikey::ApiAuthentication.new(api_id: api_id, api_key: api_key, unique_passcode: 'ccccccbtcvvhgnvvbivkdfkrddgiikfkdhjlhgeinhlb')
        expect(authentication.status).to eq('BAD_OTP')
      end
    end
  end

  context 'raises ArgumentError when' do
    it 'API ID is missing' do
      expect{ Rubikey::ApiAuthentication.new(api_key: api_key, unique_passcode: unique_passcode) }.to raise_error(ArgumentError)
    end

    it 'API key is missing' do
      expect{ Rubikey::ApiAuthentication.new(api_id: api_id, unique_passcode: unique_passcode) }.to raise_error(ArgumentError)
    end
  end
end
