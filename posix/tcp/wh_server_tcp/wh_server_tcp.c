/*
 * Example server app using POSIX TCP transport
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <stdlib.h> /* For atoi */
#include <string.h> /* For memset, memcpy, strcmp */
#include <unistd.h> /* For sleep */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "port/posix/posix_transport_tcp.h"

/** Local declarations */
static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId);

enum {
    ONE_MS         = 1000,
    FLASH_RAM_SIZE = 1024 * 1024,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_SERVER_ID 57

static int loadAndStoreKeys(whServerContext* server, whKeyId* outKeyId,
                            const char* keyFilePath, int keyId, int clientId)
{
    int           ret;
    int           keyFd;
    int           keySz;
    char          keyLabel[] = "baby's first key";
    uint8_t       keyBuf[4096];
    whNvmMetadata meta = {0};

    /* open the key file */
    ret = keyFd = open(keyFilePath, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFilePath, ret);
        return ret;
    }

    /* read the key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFilePath, ret);
        close(keyFd);
        return ret;
    }
    ret = 0;
    close(keyFd);

    printf("Loading key from %s (size=%d) with keyId=0x%02X and clientId=0x%01X\n",
           keyFilePath, keySz, keyId, clientId);

    /* cache the key in the HSM, get HSM assigned keyId */
    /* set the metadata fields */
    meta.id    = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, clientId, keyId);
    meta.flags = 0;
    meta.len   = keySz;
    memcpy(meta.label, keyLabel, strlen(keyLabel));

    /* Get HSM assigned keyId if not set */
    if (keyId == WH_KEYID_ERASED) {
        ret = hsmGetUniqueId(server, &meta.id);
        printf("got unique ID = 0x%02X\n", meta.id & WH_KEYID_MASK);
    }
    printf(
        "key NVM ID = 0x%04X\n\ttype=0x%01X\n\tuser=0x%01X\n\tkeyId=0x%02X\n",
        meta.id, WH_KEYID_TYPE(meta.id), WH_KEYID_USER(meta.id),
        WH_KEYID_ID(meta.id));

    if (ret == 0) {
        ret = hsmCacheKey(server, &meta, keyBuf);
        if (ret != 0) {
            printf("Failed to hsmCacheKey, ret=%d\n", ret);
            return ret;
        }
    }
    else {
        printf("Failed to hsmGetUniqueId, ret=%d\n", ret);
        return ret;
    }

    *outKeyId = meta.id;
    return ret;
}


static int wh_ServerTask(void* cf, const char* keyFilePath, int keyId,
                         int clientId)
{
    whServerContext server[1];
    whServerConfig* config            = (whServerConfig*)cf;
    int             ret               = 0;
    whCommConnected am_connected      = WH_COMM_DISCONNECTED;
    whKeyId         loadedKeyId;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Server_Init(server, config);

    /* Load keys into cache if file path is provided */
    if (keyFilePath != NULL) {
        ret = loadAndStoreKeys(server, &loadedKeyId, keyFilePath, keyId,
                               clientId);
        if (ret != 0) {
            printf("server failed to load key, ret=%d\n", ret);
            (void)wh_Server_Cleanup(server);
            return ret;
        }
    }


    if (ret == 0) {
        printf("Waiting for connection...\n");
        while (1) {
            ret = wh_Server_HandleRequestMessage(server);
            if (ret == WH_ERROR_NOTREADY) {
                usleep(ONE_MS);
            }
            else if (ret != WH_ERROR_OK) {
                printf("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
                break;
            }
            else {
                whCommConnected current_state;
                int             get_conn_result =
                    wh_Server_GetConnected(server, &current_state);
                if (get_conn_result == WH_ERROR_OK) {
                    if (current_state == WH_COMM_CONNECTED &&
                        am_connected == WH_COMM_DISCONNECTED) {
                        printf("Server connected\n");
                        am_connected = WH_COMM_CONNECTED;
                    }
                    else if (current_state == WH_COMM_DISCONNECTED &&
                             am_connected == WH_COMM_CONNECTED) {
                        printf("Server disconnected\n");
                        am_connected = WH_COMM_DISCONNECTED;

                        /* Cleanup the server */
                        (void)wh_Server_Cleanup(server);

                        /* Reinitialize the server */
                        ret = wh_Server_Init(server, config);
                        if (ret != 0) {
                            printf("Failed to reinitialize server: %d\n", ret);
                            break;
                        }

                        if (keyFilePath != NULL) {
                            ret = loadAndStoreKeys(server, &loadedKeyId, keyFilePath, keyId,
                               clientId);
                            if (ret != 0) {
                                printf("server failed to load key, ret=%d\n", ret);
                                break;
                            }
                        }
                    }
                }
                else {
                    printf("Failed to get connection state: %d\n",
                           get_conn_result);
                }
            }
        }
    }
    return ret;
}

int main(int argc, char** argv)
{
    int         rc          = 0;
    const char* keyFilePath = NULL;
    int         keyId = WH_KEYID_ERASED; /* Default key ID if none provided */
    int         clientId = 12; /* Default client ID if none provided */

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            keyFilePath = argv[++i];
        }
        else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            keyId = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) {
            clientId = atoi(argv[++i]);
        }
    }

    /* Server configuration/context */
    whTransportServerCb            ptttcb[1]      = {PTT_SERVER_CB};
    posixTransportTcpServerContext tsc[1]         = {};
    posixTransportTcpConfig        mytcpconfig[1] = {{
               .server_ip_string = WH_SERVER_TCP_IPSTRING,
               .server_port      = WH_SERVER_TCP_PORT,
    }};
    whCommServerConfig             cs_conf[1]     = {{
                        .transport_cb      = ptttcb,
                        .transport_context = (void*)tsc,
                        .transport_config  = (void*)mytcpconfig,
                        .server_id         = WH_SERVER_ID,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
    }};

    rc = wh_Nvm_Init(nvm, n_conf);
    if (rc != 0) {
        printf("Failed to initialize NVM: %d\n", rc);
        return rc;
    }
    /* Initialize crypto library and hardware */
    wolfCrypt_Init();

    wc_InitRng_ex(crypto->rng, NULL, crypto->devId);

    rc = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
    if (rc != 0) {
        printf("Failed to wc_InitRng_ex: %d\n", rc);
        return rc;
    }

    rc = wh_ServerTask(s_conf, keyFilePath, keyId, clientId);

    return rc;
}
