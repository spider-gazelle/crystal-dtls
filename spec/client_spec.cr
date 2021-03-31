require "./spec_helper"

module DTLS
  describe Socket::Client do
    it "negotiate a connection" do
      tls = Context::Client.new(LibSSL.dtls_method)
      # LibSSL.ssl_ctx_set_min_proto_version tls, LibSSL::DTLS1_VERSION
      # LibSSL.ssl_ctx_ctrl(tls, LibSSL::SSL_CTRL_SET_MIN_PROTO_VERSION, LibSSL::DTLS1_2_VERSION, nil)

      tls.verify_mode = OpenSSL::SSL::VerifyMode::NONE

      # optional
      # https://community.cisco.com/t5/vpn/anyconnect-new-feature-dtlsv1-2/td-p/3758577
      # https://docs.citrix.com/en-us/citrix-adc/current-release/ssl/support-for-dtls-protocol.html
      # tls.ciphers = "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384"

      client = UDPSocket.new
      client.connect "localhost", 4444
      socket = DTLS::Socket::Client.new(client, context: tls, sync_close: true, hostname: "localhost")
      socket.write "testing".to_slice
      socket.flush

      socket.write "other\n".to_slice
      socket.flush

      socket.gets.should eq("testingother")
      socket.close
    end
  end
end
