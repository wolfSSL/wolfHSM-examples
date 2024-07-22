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

    /* Crypto demos */
    rc = wh_DemoClient_CryptoRsa(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoRsaImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCurve25519(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCurve25519Import(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoEcc(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoEccImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesCbc(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesCbcImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesGcm(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoAesGcmImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmac(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    rc = wh_DemoClient_CryptoCmacOneshotImport(clientContext);
    if (rc != 0) {
        return rc;
    }

    return rc;
}
