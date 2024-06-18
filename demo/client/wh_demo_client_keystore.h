#ifndef CLIENT_KEYSTORE_H_
#define CLIENT_KEYSTORE_H_
#include "wolfhsm/wh_client.h"

int client_keystore_demo_basic(whClientContext* clientContext);
int client_keystore_demo_committed_key(whClientContext* clientContext);
int client_keystore_demo_aes(whClientContext* clientContext);

#endif /* CLIENT_KEYSTORE_H_ */