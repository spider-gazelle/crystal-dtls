# Crystal Lang DTLS Support

[![CI](https://github.com/spider-gazelle/crystal-dtls/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/crystal-dtls/actions/workflows/ci.yml)

Communicate over UDP securely with DTLS

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     dtls:
       github: spider-gazelle/crystal-dtls
   ```

2. Run `shards install`


## Usage

```crystal

require "dtls"

host = UDPSocket.new
host.connect "dtls.server", 4444

# Wrap the UDP connection
socket = DTLS::Socket::Client.new(host)

# Communicate over DTLS
socket << "request"
socket.flush

response = socket.gets

socket.close

```
