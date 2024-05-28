# wolfHSM-examples

## Current Examples
Currently, the only public example for wolfHSM uses the POSIX simulator. If you are interested in examples for NDA-restricted hardware platforms, please contact us at support@wolfssl.com.

### Posix TCP server and client
This example spawns a wolfHSM client and server, both in their own thread, and runs the client-side unit tests against the server. server.

### Building
To build the client and the server, wolfHSM must be configured and built along side wolfSSL.

In the Makefile for both the server and client in `wolfHSM-examples/posix/tcp/wh_<client or server>_tcp/` under important directories is as follows :
```
# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../../../../wolfHSM

WOLFSSL_DIR ?= $(CURDIR)/../../../../wolfssl
```

Set the `WOLFHSM_DIR` and `WOLFSSL_DIR` variables to point to your local installation of wolfHSM and wolfSSL. Now the client and server demo application can be built.

### Building wh_server_tcp
`cd` into `wolfHSM-examples/posix/tcp/wh_server_tcp` and run `make`. Once completed, the output server executable `wh_server_tcp.elf` will be located in the `Build` directory.`

### Building wh_client_tcp
`cd` into `wolfHSM-examples/posix/tcp/wh_client_tcp` and run `make`. Once completed, the output server executable `wh_client_tcp.elf` will be located in the `Build` directory.

### Executables
In the root directory for wolfHSM-examples run `./posix/tcp/wh_server_tcp/Build/wh_server_tcp.elf` to launch the server. In a separate shell, run `./posix/tcp/wh_client_tcp/Build/wh_client_tcp.elf` to launch the client.

### Results
After all steps are you complete you should see the following outputs.

Server output :
```
wh_Server_Init:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
Server HandleRequestMessage:0
ServerCleanup:0
```

Client output :
```
wh_Client_Init:0
Client EchoRequest:0, len:9, Request:0
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:0
Client EchoRequest:0, len:9, Request:1
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:1
Client EchoRequest:0, len:9, Request:2
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:2
Client EchoRequest:0, len:9, Request:3
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:3
Client EchoRequest:0, len:9, Request:4
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:4
Client EchoRequest:0, len:9, Request:5
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:5
Client EchoRequest:0, len:9, Request:6
Client EchoResponse:-401, len:0,
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:6
Client EchoRequest:0, len:9, Request:7
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:7
Client EchoRequest:0, len:9, Request:8
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:8
Client EchoRequest:0, len:9, Request:9
Client EchoResponse:-401, len:0,
Client EchoResponse:0, len:9, Request:9
wh_Client_Cleanup:0
```
