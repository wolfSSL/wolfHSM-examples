#include "client_demo_driver.h"
#include "client_nvm.h"

int client_demo_driver(whClientContext* clientContext)
{
    int rc = 0;

    rc = client_nvm_demo(clientContext);
    if (rc != 0) {
        return rc;
    }

    return rc;
}


