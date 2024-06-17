#include "client_demo_driver.h"
#include "client_nvm.h"
#include "client_keystore.h"

int client_demo_driver(whClientContext* clientContext)
{
    int rc = 0;

    /* NVM demos */
    rc = client_nvm_demo(clientContext);
    if (rc != 0) {
        return rc;
    }

    /* Keystore demos */
    rc = client_keystore_demo_basic(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = client_keystore_demo_committed_key(clientContext);
    if (rc != 0) {
        return rc;
    }
    rc = client_keystore_demo_aes(clientContext);
    if (rc != 0) {
        return rc;
    }

    return rc;
}
