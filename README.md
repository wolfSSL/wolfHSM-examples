# wolfHSM-examples

## Current Examples

### Posix TCP server and client
The only example currently is a Posix tcp server and client.

### Building
To build the client and the server wolfHSM must be configured and built along side wolfSSL.

In the Makefile for both the server and client in `wolfHSM-examples/posix/tcp/wh_<client or server>_tcp/` under important directories is as follows :
```
# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../../../../wolfHSM

WOLFSSL_DIR ?= $(CURDIR)/../../../../wolfssl
```
After making sure the `WOLFHSM_DIR` matches the directory name downloaded for wolfHSM the next step is building the client and server.
### Building wh_server_tcp
cd into `wolfHSM-examples/posix/tcp/wh_server_tcp` run `make`. Once completed an `.elf` excutable will be made in `Build` named `wh_server_tcp.elf`.

### Building wh_client_tcp
cd into `wolfHSM-examples/posix/tcp/wh_client_tcp` run `make`. Once completed an `.elf` excutable will be made in `Build` named `wh_client_tcp.elf`. 

### Executables
Once both the server and the client `.elf` files have been made the example can now be ran. In the root directory for wolfHSM-examples run `./posix/tcp/wh_server_tcp/Build/wh_server_tcp.elf`.
In a sperate instnace run `./posix/tcp/wh_client_tcp/Build/wh_client_tcp.elf` out of the root directory for wolfHSM-examples for the client.

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