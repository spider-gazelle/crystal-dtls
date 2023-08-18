require "socket"
require "./bio"

lib LibSSL
  DTLS1_VERSION                  = 0xFEFF
  DTLS1_2_VERSION                = 0xFEFD
  SSL_CTRL_SET_MIN_PROTO_VERSION =    123

  # not required
  # fun dtls_client_method = DTLS_client_method : SSLMethod
end

abstract class DTLS::Socket < IO
  class Client < DTLS::Socket
    def initialize(io : UDPSocket, context : Context::Client = Context::Client.new(LibSSL.dtls_method), sync_close : Bool = false, hostname : String? = nil)
      super(io, nil, context, sync_close)
      begin
        if hostname
          # Macro from OpenSSL: SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)
          LibSSL.ssl_ctrl(
            @ssl,
            LibSSL::SSLCtrl::SET_TLSEXT_HOSTNAME,
            LibSSL::TLSExt::NAMETYPE_host_name,
            hostname.to_unsafe.as(Pointer(Void))
          )

          {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0 %}
            param = LibSSL.ssl_get0_param(@ssl)

            if ::Socket::IPAddress.valid?(hostname)
              unless LibCrypto.x509_verify_param_set1_ip_asc(param, hostname) == 1
                raise OpenSSL::Error.new("X509_VERIFY_PARAM_set1_ip_asc")
              end
            else
              unless LibCrypto.x509_verify_param_set1_host(param, hostname, 0) == 1
                raise OpenSSL::Error.new("X509_VERIFY_PARAM_set1_host")
              end
            end
          {% else %}
            context.set_cert_verify_callback(hostname)
          {% end %}
        end

        # This allows for packet retransmission / out of order receive
        # LibSSL.ssl_ctx_set_options(tls, LibSSL::Options::NO_COMPRESSION)
        context.add_options(OpenSSL::SSL::Options::NO_COMPRESSION)

        ret = LibSSL.ssl_connect(@ssl)
        unless ret == 1
          raise OpenSSL::SSL::Error.new(@ssl, ret, "SSL_connect")
        end
      rescue ex
        LibSSL.ssl_free(@ssl) # GC never calls finalize, avoid mem leak
        raise ex
      end
    end

    def self.open(io, context : Context::Client = Context::Client.new(LibSSL.dtls_method), sync_close : Bool = false, hostname : String? = nil)
      socket = new(io, context, sync_close, hostname)

      begin
        yield socket
      ensure
        socket.close
      end
    end
  end

  include IO::Buffered

  # If `#sync_close?` is `true`, closing this socket will
  # close the underlying IO.
  property? sync_close : Bool

  getter? closed : Bool

  protected def initialize(io : UDPSocket, remote : ::Socket::IPAddress?, context : Context, @sync_close : Bool = false)
    @closed = false

    @ssl = LibSSL.ssl_new(context)
    unless @ssl
      raise OpenSSL::Error.new("SSL_new")
    end

    io.sync = true
    io.read_buffering = false

    @bio = BIO.new(io, remote)
    LibSSL.ssl_set_bio(@ssl, @bio, @bio)
  end

  def finalize
    LibSSL.ssl_free(@ssl)
  end

  def unbuffered_read(slice : Bytes)
    check_open

    count = slice.size
    return 0 if count == 0

    LibSSL.ssl_read(@ssl, slice.to_unsafe, count).tap do |bytes|
      if bytes <= 0 && !LibSSL.ssl_get_error(@ssl, bytes).zero_return?
        ex = OpenSSL::SSL::Error.new(@ssl, bytes, "SSL_read")
        if ex.underlying_eof?
          # underlying BIO terminated gracefully, without terminating SSL aspect gracefully first
          # some misbehaving servers "do this" so treat as EOF even though it's a protocol error
          return 0
        end
        raise ex
      end
    end
  end

  def unbuffered_write(slice : Bytes)
    check_open

    return if slice.empty?

    count = slice.size
    bytes = LibSSL.ssl_write(@ssl, slice.to_unsafe, count)
    unless bytes > 0
      raise OpenSSL::SSL::Error.new(@ssl, bytes, "SSL_write")
    end
  end

  def unbuffered_flush
    @bio.io.flush
  end

  {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0 %}
    # Returns the negotiated ALPN protocol (eg: `"h2"`) of `nil` if no protocol was
    # negotiated.
    def alpn_protocol
      LibSSL.ssl_get0_alpn_selected(@ssl, out protocol, out len)
      String.new(protocol, len) unless protocol.null?
    end
  {% end %}

  # ameba:disable Metrics/CyclomaticComplexity
  def unbuffered_close
    return if @closed
    @closed = true

    begin
      loop do
        begin
          ret = LibSSL.ssl_shutdown(@ssl)
          break if ret == 1                # done bidirectional
          break if ret == 0 && sync_close? # done unidirectional, "this first successful call to SSL_shutdown() is sufficient"
          raise OpenSSL::SSL::Error.new(@ssl, ret, "SSL_shutdown") if ret < 0
        rescue e : OpenSSL::SSL::Error
          case e.error
          when .want_read?, .want_write?
            # Ignore, shutdown did not complete yet
          when .syscall?
            # OpenSSL claimed an underlying syscall failed, but that didn't set any error state,
            # assume we're done
            break
          else
            raise e
          end
        end

        # ret == 0, retry, shutdown is not complete yet
      end
    rescue IO::Error
    ensure
      @bio.io.close if @sync_close
    end
  end

  def unbuffered_rewind
    raise IO::Error.new("Can't rewind DTLS::Socket::Client")
  end

  # Returns the hostname provided through Server Name Indication (SNI)
  def hostname : String?
    if host_name = LibSSL.ssl_get_servername(@ssl, LibSSL::TLSExt::NAMETYPE_host_name)
      String.new(host_name)
    end
  end

  # Returns the current cipher used by this socket.
  def cipher : String
    String.new(LibSSL.ssl_cipher_get_name(LibSSL.ssl_get_current_cipher(@ssl)))
  end

  # Returns the name of the TLS protocol version used by this socket.
  def tls_version : String
    String.new(LibSSL.ssl_get_version(@ssl))
  end

  def local_address
    io = @bio.io
    io.local_address
  end

  def remote_address
    io = @bio.io
    io.remote_address
  end

  def read_timeout
    io = @bio.io
    io.read_timeout
  end

  def read_timeout=(value)
    io = @bio.io
    io.read_timeout = value
  end

  def write_timeout
    io = @bio.io
    io.write_timeout
  end

  def write_timeout=(value)
    io = @bio.io
    io.write_timeout = value
  end
end
