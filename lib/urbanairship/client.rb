require 'json'
require 'rest-client'
require 'urbanairship'


module Urbanairship
    class Client
      attr_accessor :key, :secret
      include Urbanairship::Common
      include Urbanairship::Loggable

      # Initialize the Client
      #
      # @param [Object] key Application Key
      # @param [Object] secret Application Secret
      # @return [Object] Client
      def initialize(key: required('key'), secret: required('secret'))
        @key = key
        @secret = secret
      end

      # Send a request to Urban Airship's API
      #
      # @param [Object] method HTTP Method
      # @param [Object] body Request Body
      # @param [Object] url Request URL
      # @param [Object] content_type Content-Type
      # @param [Object] version API Version
      # @return [Object] Push Response
      def send_request(method: required('method'), url: required('url'), body: nil,
                       content_type: nil, encoding: nil)
        req_type = case method
          when 'GET'
            :get
          when 'POST'
            :post
          when 'PUT'
            :put
          when 'DELETE'
            :delete
          else
            fail 'Method was not "GET" "POST" "PUT" or "DELETE"'
        end

        headers = {'User-agent' => 'UARubyLib/' + Urbanairship::VERSION}
        headers['Accept'] = 'application/vnd.urbanairship+json; version=3'
        headers['Content-type'] = content_type unless content_type.nil?
        headers['Content-Encoding'] = encoding unless encoding.nil?

        debug = "Making #{method} request to #{url}.\n"+
            "\tHeaders:\n"
        debug += "\t\tcontent-type: #{content_type}\n" unless content_type.nil?
        debug += "\t\tcontent-encoding: gzip\n" unless encoding.nil?
        debug += "\t\taccept: application/vnd.urbanairship+json; version=3\n"
        debug += "\tBody:\n#{body}" unless body.nil?

        logger.debug(debug)

        begin
          response = RestClient::Request.execute(
            method: method,
            url: url,
            headers: headers,
            user: @key,
            password: @secret,
            payload: body,
            timeout: 5
          )
          logger.debug("Received #{response.code} response. Headers:\n\t#{response.headers}\nBody:\n\t#{response.body}")
          Response.check_code(response.code, response)

          self.class.build_response(response)
        rescue RestClient::ExceptionWithResponse => e
          logger.error("Received #{e.http_code} response. Headers:\n\t#{e.http_headers}\nBody:\n\t#{e.http_body}")
        rescue Exception => e
          logger.error("Unexpected exception in UA request: #{e.message}")
        end
      end

      # Create a Push Object
      #
      # @return [Object] Push Object
      def create_push
        Push::Push.new(self)
      end

      # Create a Scheduled Push Object
      #
      # @return [Object] Scheduled Push Object
      def create_scheduled_push
        Push::ScheduledPush.new(self)
      end

      # Build a hash from the response object
      #
      # @return [Hash] The response body.
      def self.build_response(response)
        response_hash = {'code'=>response.code.to_s, 'headers'=>response.headers}

        begin
          body = JSON.parse(response.body)
        rescue JSON::ParserError
          if response.body.nil? || response.body.empty?
            body = {}
          else
            body = response.body
            response_hash['error'] = 'could not parse response JSON'
          end
        end

        response_hash['body'] = body
        response_hash
      end
    end
  end
