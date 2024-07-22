#ifndef CLIENT_CRYPTO_H_
#define CLIENT_CRYPTO_H_
#include "wolfhsm/wh_client.h"

int wh_DemoClient_CryptoRsa(whClientContext* clientContext);
int wh_DemoClient_CryptoRsaImport(whClientContext* clientContext);
int wh_DemoClient_CryptoCurve25519(whClientContext* clientContext);
int wh_DemoClient_CryptoCurve25519Import(whClientContext* clientContext);
int wh_DemoClient_CryptoEcc(whClientContext* clientContext);
int wh_DemoClient_CryptoEccImport(whClientContext* clientContext);
int wh_DemoClient_CryptoAesCbc(whClientContext* clientContext);
int wh_DemoClient_CryptoAesCbcImport(whClientContext* clientContext);
int wh_DemoClient_CryptoAesGcm(whClientContext* clientContext);
int wh_DemoClient_CryptoAesGcmImport(whClientContext* clientContext);
int wh_DemoClient_CryptoCmac(whClientContext* clientContext);
int wh_DemoClient_CryptoCmacImport(whClientContext* clientContext);

#endif /* CLIENT_CRYPTO_H_ */
