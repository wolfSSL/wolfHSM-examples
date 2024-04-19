/*
 * Example server app using POSIX TCP transport
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For sleep */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "port/posix/posix_transport_tcp.h"

/** Local declarations */
static void* wh_ServerTask(void* cf);

enum {
	ONE_MS = 1000,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 5678

static void* wh_ServerTask(void* cf)
{
    whServerContext server[1];
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    whCommConnected am_connected = WH_COMM_CONNECTED;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Server_Init(server, config);
    printf("wh_Server_Init:%d\n", ret);

    if (ret == 0) {
        wh_Server_SetConnected(server, am_connected);

        while(am_connected == WH_COMM_CONNECTED) {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret == WH_ERROR_NOTREADY) {
                usleep(ONE_MS);
            } else if (ret == WH_ERROR_OK) {
                printf("Server HandleRequestMessage:%d\n",ret);
            } else {
                printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
                break;
            }
            wh_Server_GetConnected(server, &am_connected);
        }
        ret = wh_Server_Cleanup(server);
        printf("ServerCleanup:%d\n", ret);
    }
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
            .comm_config = cs_conf,
    }};

    wh_ServerTask(s_conf);

    return 0;
}



