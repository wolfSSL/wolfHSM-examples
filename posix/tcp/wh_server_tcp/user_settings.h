#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H
/* Server wolfSSL settings */

/* wolfHSM Required */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

#define WOLFCRYPT_ONLY

/* #define DEBUG_CRYPTOCB */
/* #define DEBUG_CRYPTOCB_VERBOSE */

/* Key gen is currently required on the server */
#define WOLFSSL_KEY_GEN
#define HAVE_CURVE25519
#define HAVE_ECC
#define HAVE_AESGCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC

#endif  /*define USER_SETTINGS_H */

