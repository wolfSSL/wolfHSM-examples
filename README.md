# wolfHSM-examples

This repository contains examples code demonstrating how to use various wolfHSM features. The examples provided are split between port-agnostic demo code, and port-specific server/client applications that use the aformentioned demo code.

- `demo/`: port-agnostic demonstration code (`demo/`). This code is intended to be used as a reference for how to use wolfHSM features, and are organized by high-level wolfHSM feature.
- `port/`: Example server and client applications for each port. These applications initialize the server and client context and then run the demo code.

## Current Examples
Currently, the only public example for wolfHSM uses the POSIX simulator. If you are interested in examples for NDA-restricted hardware platforms, please contact us at support@wolfssl.com.

### Posix TCP server and client
This example spawns a wolfHSM client and server, both in their own thread, and runs the client-side unit tests against the server.

### Using the Demo Script
A convenience script `run_posix_demo.sh` is provided to automate building and running the POSIX TCP examples:

```bash
# Set environment variables for wolfSSL and wolfHSM directories
export WOLFSSL_DIR=/path/to/wolfssl
export WOLFHSM_DIR=/path/to/wolfhsm

# Run the demo
./run_posix_demo.sh
```

The script will:
1. Build both server and client components
2. Start the server and wait for it to be ready
3. Run the client examples against the server
4. Clean up processes properly on exit

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

### Loading a key on the server
The example server supports loading a key at a specific keyId, passed as arguments on the command line. To load a key at a keyId in the server example, invoke the server with the `--key` and `--id` arguments.

```
./wh_server_tcp.elf --key /path/to/key.der --id <keyId>
```

### Results
After all steps are you complete you should see the following outputs.

Server output :

```
Waiting for connection...
Successful connection!
Server disconnected
```

Client output :

```
Client connecting to server...
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client sent request successfully
Client disconnected
```
