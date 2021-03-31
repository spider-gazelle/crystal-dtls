require "socket"
require "openssl"

module DTLS
  Log = ::Log.for("DTLS")

  alias Context = OpenSSL::SSL::Context

  BIO_CTRL_DGRAM_CONNECT       = 11
  BIO_CTRL_DGRAM_SET_CONNECTED = 32
  BIO_CTRL_DGRAM_SET_PEER      = 44
  BIO_CTRL_DGRAM_GET_PEER      = 46
  BIO_CTRL_WPENDING            = 13

  BIO_CTRL_DGRAM_QUERY_MTU        = 40
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47

  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49
  BIO_CTRL_DGRAM_SET_PEEK_MODE    = 71
  BIO_CTRL_PUSH                   =  6
  BIO_CTRL_POP                    =  7
  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45
end

require "./dtls/*"
