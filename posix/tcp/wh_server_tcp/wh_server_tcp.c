/*
 * Example server app using POSIX TCP transport
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For sleep */

#if 0
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"
#endif


#include "wolfhsm/wh_error.h"

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_flash.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "port/posix/posix_transport_tcp.h"

/** Local declarations */
static void* wh_ServerTask(void* cf);

enum {
	REPEAT_COUNT = 10,
	ONE_MS = 1000,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 5678

static void* wh_ServerTask(void* cf)
{
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    whServer server[1];
    int counter = 1;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Server_Init(server, config);
    printf("wh_Server_Init:%d\n", ret);

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        do {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret != WH_ERROR_NOTREADY) {
                printf("Server HandleRequestMessage:%d\n",ret);
            }
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        } else {
            printf("Server processed message %d of %d\n", counter + 1, REPEAT_COUNT);
        }
    }
    ret = wh_Server_Cleanup(server);
    printf("ServerCleanup:%d\n", ret);

    return NULL;
}

int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    /* Server configuration/context */
    whTransportServerCb ptttcb[1] = {PTT_SERVER_CB};
    posixTransportTcpServerContext tsc[1] = {};
    posixTransportTcpConfig mytcpconfig[1] = {{
            .server_ip_string = WH_SERVER_TCP_IPSTRING,
            .server_port = WH_SERVER_TCP_PORT,
    }};
    whCommServerConfig cs_conf[1] = {{
            .transport_cb = ptttcb,
            .transport_context = (void*)tsc,
            .transport_config = (void*)mytcpconfig,
            .server_id = WH_SERVER_ID,
    }};
    whServerConfig s_conf[1] = {{
            .comm = cs_conf,
    }};

    wh_ServerTask(s_conf);

    return 0;
}



