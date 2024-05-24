# wolfHSM-examples
## Current Examples

#### TCP server and client
The only example currently is a tcp server and client.

In the Makefile for both the server and client in `wolfHSM-examples/posix/tcp/wh_<client or server>_tcp/` under important directories is as follows :
```
# Important directories
BUILD_DIR = ./Build
WOLFHSM_DIR = $(CURDIR)/../../../../wolfHSM

WOLFSSL_DIR ?= $(CURDIR)/../../../../wolfssl
```
Take note of the name of the wolfHSM directory and make sure it matches in order to build. After completing these changes (If needed) the wh_client_tcp.elf and wh_client_tcp.elf located in `wolfHSM-examples/posix/tcp/wh_<client or server>_tcp/Build` will be executable.
