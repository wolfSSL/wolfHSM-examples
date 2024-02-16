
WOLFHSM_DIR ?= ../../wolfhsm
WOLFHSM_SRC ?= $(WOLFHSM_DIR)/src
WOLFHSM_OBJS ?= $(WOLFHSM_SRC)/wh_client.o \
                $(WOLFHSM_SRC)/wh_server.o \
                $(WOLFHSM_SRC)/comm.o \
                $(WOLFHSM_SRC)/message_comm.o \
                $(WOLFHSM_SRC)/shmbuffer.o \
                $(WOLFHSM_SRC)/transport_shm.o

WOLFSSL_DIR ?= $(WOLFHSM_DIR)/wolfssl
WOLFCRYPT_SRC ?= $(WOLFSSL_DIR)/wolfcrypt/src
WOLFCRYPT_OBJS ?= $(WOLFCRYPT_SRC)/port.o
 
WOLFHSM_PORT ?= $(WOLFHSM_DIR)/port
PORT_OBJS ?= $(WOLFHSM_PORT)/posix/transport_tcp.o

COMMON_INCS ?= -I$(WOLFHSM_DIR) -I$(WOLFSSL_DIR)
CFLAGS += $(COMMON_INCS) -DWOLFSSL_USER_SETTINGS

CLIENT_OBJS ?= wh_client_tcp/wh_client_tcp.o

SERVER_OBJS ?= wh_server_tcp/wh_server_tcp.o

all: wh_client_tcp wh_server_tcp

wh_client_tcp: $(CLIENT_OBJS) $(PORT_OBJS) $(WOLFHSM_OBJS)
	$(CC) -o wh_client_tcp/$@ $^

wh_server_tcp: $(SERVER_OBJS) $(PORT_OBJS) $(WOLFHSM_OBJS)
	$(CC) -o wh_server_tcp/$@ $^

