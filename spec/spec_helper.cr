require "spec"
require "system"
require "../src/dtls"

::Log.setup("*", :trace)

def generate_private_key(file_name : String)
  err_out = IO::Memory.new
  result = Process.run(
    "openssl",
    {"genpkey", "-algorithm", "RSA", "-out", file_name},
    error: err_out
  )
  if result.success?
    puts "Generated private key: #{file_name}"
  else
    raise "Error generating private key: #{err_out.to_slice}"
  end
end

def generate_self_signed_cert(key_file : String, cert_file : String)
  # Pre-fill certificate information for automation.
  # Note: Adjust this as per your requirements.
  subj = "/C=US/ST=ExampleState/L=ExampleLocality/O=ExampleOrg/CN=example.com"

  err_out = IO::Memory.new
  result = Process.run(
    "openssl",
    {"req", "-new", "-x509", "-key", key_file, "-out", cert_file, "-days", "365", "-subj", subj},
    error: err_out
  )
  if result.success?
    puts "Generated certificate: #{cert_file}"
  else
    raise "Error generating certificate: #{String.new(err_out.to_slice)}"
  end
end

def launch_dtls_server(shutdown_channel : Channel(Nil))
  print "lunching DTLS echo server... "
  ready_channel = Channel(Nil).new
  # Launch OpenSSL test server
  spawn do
    # Run the s_server in the Fiber
    # "openssl", {"s_server", "-dtls1_2", "-key", "yourkey.pem", "-cert", "yourcert.pem", "-port", "4444"},

    Process.run(
      "./dtls_server",
      {"4444"},
      output: :inherit,
      error: :inherit
    ) do |process|
      # signal when the process is running
      sleep 1
      puts "[ready]"
      ready_channel.send nil

      # Wait for a shutdown signal
      shutdown_channel.receive

      # Once signal received, kill the s_server process
      process.terminate graceful: false
      process.wait

      puts "s_server has been shut down."
    end
  end
  ready_channel.receive
end

# generate some encryption keys
unless File.exists?("yourkey.pem")
  generate_private_key("yourkey.pem")
  generate_self_signed_cert("yourkey.pem", "yourcert.pem")
end

# generate our DTLS test server
unless File.exists?("./dtls_server")
  err_out = IO::Memory.new
  result = Process.run(
    "g++",
    {"examples/dtls_server.cpp", "-o", "dtls_server", "-lssl", "-lcrypto"},
    error: err_out
  )
  if result.success?
    puts "Built DTLS test server"
  else
    puts "Error generating test server: #{String.new(err_out.to_slice)}"
  end
end

# Channel to signal the fiber to shutdown the s_server
shutdown_channel = Channel(Nil).new
launch_dtls_server(shutdown_channel)
