/*
 * wolfHSM Client TCP Example
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For usleep */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"
#include "port/posix/posix_transport_tcp.h"

#include "wh_demo_client_all.h"

/** Local declarations */
static void* wh_ClientTask(void* cf);


enum {
	REPEAT_COUNT = 10,
	REQ_SIZE = 32,
	RESP_SIZE = 64,
	ONE_MS = 1000,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_CLIENT_ID 12

static void* wh_ClientTask(void* cf)
{
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;
    whClientContext client[1];
    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len = 0;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Client_Init(client, config);
    printf("Client connecting to server...\n");

    if (ret != 0) {
        perror("Init error:");
        return NULL;
    }
    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        sprintf((char*)tx_req,"Request:%u",counter);
        tx_req_len = strlen((char*)tx_req);
        do {
            ret = wh_Client_EchoRequest(client,
                    tx_req_len, tx_req);
            if (ret != WH_ERROR_NOTREADY) {
                if (ret == 0) {
                    printf("Client sent request successfully\n");
                } else {
                    printf("wh_CLient_EchoRequest failed with ret=%d\n", ret);
                }
            }
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(client,
                    &rx_resp_len, rx_resp);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }
    }

    /* run the client demos */
    ret = client_demo_driver(client);
    if (ret != 0) {
        printf("Client demo failed: ret=%d\n", ret);
    }


    wh_Client_CommClose(client);
    ret = wh_Client_Cleanup(client);
    printf("Client disconnected\n");
    return NULL;
}

int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    /* Client configuration/contexts */
    whTransportClientCb pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1] = {};
    posixTransportTcpConfig mytcpconfig[1] = {{
            .server_ip_string = WH_SERVER_TCP_IPSTRING,
            .server_port = WH_SERVER_TCP_PORT,
    }};

    whCommClientConfig cc_conf[1] = {{
            .transport_cb = pttccb,
            .transport_context = (void*)tcc,
            .transport_config = (void*)mytcpconfig,
            .client_id = WH_CLIENT_ID,
    }};
    whClientConfig c_conf[1] = {{
            .comm = cc_conf,
    }};

    wh_ClientTask(c_conf);

    return 0;
}



