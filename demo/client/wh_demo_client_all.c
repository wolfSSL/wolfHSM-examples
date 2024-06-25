#include "wh_demo_client_all.h"
#include "wh_demo_client_nvm.h"
#include "wh_demo_client_keystore.h"

int wh_DemoClient_All(whClientContext* clientContext)
{
    int rc = 0;

    /* NVM demos */
    rc = wh_DemoClient_Nvm(clientContext);
    if (rc != 0) {
        return rc;
    }

    /* Keystore demos */
    rc = wh_DemoClient_KeystoreBasic(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = wh_DemoClient_KeystoreCommitKey(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = wh_DemoClient_KeystoreAes(clientContext);
    if (rc != 0) {
        return rc;
    }

    return rc;
}
