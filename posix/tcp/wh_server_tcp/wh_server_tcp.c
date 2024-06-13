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
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "port/posix/posix_transport_tcp.h"

/** Local declarations */
static void* wh_ServerTask(void* cf);

enum {
	ONE_MS = 1000,
    FLASH_RAM_SIZE = 1024 * 1024,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 56

static void* wh_ServerTask(void* cf)
{
    whServerContext server[1];
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    int connectionMessage = 0;
    whCommConnected am_connected = WH_COMM_CONNECTED;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Server_Init(server, config);
    printf("Waiting for connection...\n");

    if (ret == 0) {
        wh_Server_SetConnected(server, am_connected);

        while (am_connected == WH_COMM_CONNECTED) {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret == WH_ERROR_NOTREADY) {
                usleep(ONE_MS);
            } else if (ret == WH_ERROR_OK) {
                if (!connectionMessage) {
                    printf("Successful connection!\n");
                    connectionMessage = 1;
                }
            } else {
                printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
                break;
            }
            wh_Server_GetConnected(server, &am_connected);
        }
        ret = wh_Server_Cleanup(server);
        printf("Server disconnected\n");
    }
    return NULL;
}

int main(int argc, char** argv)
{
    (void)argc; (void)argv;
    int rc = 0;

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

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE/2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig nf_conf[1] = {{
        .cb      = fcb,
        .context = fc,
        .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1] = {0};
    whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

    whNvmConfig n_conf[1] = {{
            .cb = nfcb,
            .context = nfc,
            .config = nf_conf,
    }};
    whNvmContext nvm[1] = {{0}};

    whServerConfig s_conf[1] = {{
            .comm_config = cs_conf,
            .nvm = nvm,
    }};

    rc = wh_Nvm_Init(nvm, n_conf);
    if (rc != 0) {
        printf("Failed to initialize NVM: %d\n", rc);
        return rc;
    }

    wh_ServerTask(s_conf);

    return 0;
}



