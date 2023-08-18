require "../dtls"

struct DTLS::BIO
  def self.get_data(bio) : Void*
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      LibCrypto.BIO_get_data(bio)
    {% else %}
      bio.value.ptr
    {% end %}
  end

  def self.set_data(bio, data : Void*)
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      LibCrypto.BIO_set_data(bio, data)
    {% else %}
      bio.value.ptr = data
    {% end %}
  end

  DTLS_BIO = begin
    bwrite = LibCrypto::BioMethodWriteOld.new do |bio, data, len|
      io, remote = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).unbox(BIO.get_data(bio))
      if remote
        io.send Slice.new(data, len), remote
      else
        io.send Slice.new(data, len)
      end
      len
    end

    bwrite_ex = LibCrypto::BioMethodWrite.new do |bio, data, len, writep|
      count = len > Int32::MAX ? Int32::MAX : len.to_i
      io, remote = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).unbox(BIO.get_data(bio))
      if remote
        io.send Slice.new(data, count), remote
      else
        io.send Slice.new(data, count)
      end
      writep.value = LibC::SizeT.new(count)
      1
    end

    bread = LibCrypto::BioMethodReadOld.new do |bio, buffer, len|
      io, _remote = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).unbox(BIO.get_data(bio))
      io.flush
      io.read(Slice.new(buffer, len)).to_i
    end

    bread_ex = LibCrypto::BioMethodWrite.new do |bio, buffer, len, readp|
      count = len > Int32::MAX ? Int32::MAX : len.to_i
      io, _remote = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).unbox(BIO.get_data(bio))
      io.flush
      ret = io.read Slice.new(buffer, count)
      readp.value = LibC::SizeT.new(ret)
      1
    end

    ctrl = LibCrypto::BioMethodCtrl.new do |bio, cmd, num, ptr|
      io, _remote = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).unbox(BIO.get_data(bio))

      val = case cmd
            when BIO_CTRL_DGRAM_CONNECT, BIO_CTRL_DGRAM_SET_CONNECTED, BIO_CTRL_DGRAM_SET_PEER, BIO_CTRL_DGRAM_GET_PEER
              io.flush
              1
            when BIO_CTRL_WPENDING, BIO_CTRL_PUSH, BIO_CTRL_POP, BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT
              0
            when LibCrypto::CTRL_SET_KTLS_SEND
              0
            when LibCrypto::CTRL_GET_KTLS_SEND, LibCrypto::CTRL_GET_KTLS_RECV
              0
            when BIO_CTRL_DGRAM_QUERY_MTU, BIO_CTRL_DGRAM_GET_FALLBACK_MTU
              1500
            when BIO_CTRL_DGRAM_GET_MTU_OVERHEAD
              # random guess
              96
            when BIO_CTRL_DGRAM_SET_PEEK_MODE
              # TODO:: convert this from c-code
              # ((custom_bio_data_t *)BIO_get_data(bio))->peekmode = !!num;
              # 1
              0
            else
              STDERR.puts "WARNING: Unsupported BIO ctrl call (#{cmd})"
              0
            end
      LibCrypto::Long.new(val)
    end

    create = LibCrypto::BioMethodCreate.new do |bio|
      {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
        LibCrypto.BIO_set_shutdown(bio, 1)
        LibCrypto.BIO_set_init(bio, 1)
        # bio.value.num = -1
      {% else %}
        bio.value.shutdown = 1
        bio.value.init = 1
        bio.value.num = -1
      {% end %}
      1
    end

    destroy = LibCrypto::BioMethodDestroy.new do |bio|
      BIO.set_data(bio, Pointer(Void).null)
      1
    end

    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      biom = LibCrypto.BIO_meth_new(Int32::MAX, "DTLS BIO")

      {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.1") >= 0 %}
        LibCrypto.BIO_meth_set_write_ex(biom, bwrite_ex)
        LibCrypto.BIO_meth_set_read_ex(biom, bread_ex)
      {% else %}
        LibCrypto.BIO_meth_set_write(biom, bwrite)
        LibCrypto.BIO_meth_set_read(biom, bread)
      {% end %}

      LibCrypto.BIO_meth_set_ctrl(biom, ctrl)
      LibCrypto.BIO_meth_set_create(biom, create)
      LibCrypto.BIO_meth_set_destroy(biom, destroy)
      biom
    {% else %}
      biom = Pointer(LibCrypto::BioMethod).malloc(1)
      biom.value.type_id = Int32::MAX
      biom.value.name = "DTLS BIO"
      biom.value.bwrite = bwrite
      biom.value.bread = bread
      biom.value.ctrl = ctrl
      biom.value.create = create
      biom.value.destroy = destroy
      biom
    {% end %}
  end

  @boxed_io : Void*

  def initialize(@io : UDPSocket, @remote : ::Socket::IPAddress?)
    @bio = LibCrypto.BIO_new(DTLS_BIO)

    # We need to store a reference to the box because it's
    # stored in `@bio.value.ptr`, but that lives in C-land,
    # not in Crystal-land.
    @boxed_io = Box(Tuple(UDPSocket, ::Socket::IPAddress?)).box({io, remote})

    BIO.set_data(@bio, @boxed_io)
  end

  getter io, remote

  def to_unsafe
    @bio
  end
end
