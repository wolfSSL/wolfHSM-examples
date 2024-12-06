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
#define SINGLE_THREADED
#define WC_NO_ASYNC_THREADING
#define WOLFSSL_USE_ALIGN
#define HAVE_WC_INTROSPECTION
#define WOLFSSL_IGNORE_FILE_WARN

/* Define the following to remove dynamic memory allocation
 * Note: This is incompatible with ML-DSA, so OFF by default */
#if 0
#define WOLFSSL_NO_MALLOC
#endif

/* Hardening options */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Remove unneeded features*/
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_FILESYSTEM
#define NO_INLINE
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define NO_DO178

/* Remove unneded namespace */
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/* RSA Options */
//#define NO_RSA
#define HAVE_RSA
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define FP_MAX_BITS 8192

/* ECC Options */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_SUPPORTED_CURVES

/* Curve25519 Options */
#define HAVE_CURVE25519

/* AES options */
#define HAVE_AESGCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC

/* Dilithium Options */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM /* use wolfCrypt implementation, not libOQS */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* The following options can be individually controlled to customize the
 * ML-DSA configuration */
#if 0
#define WOLFSSL_DILITHIUM_VERIFY_ONLY
#endif
#if 0
#define WOLFSSL_DILITHIUM_NO_VERIFY
#endif
#if 0
#define WOLFSSL_DILITHIUM_NO_SIGN
#endif
#if 0
#define WOLFSSL_DILITHIUM_NO_MAKE_KEY
#endif


/* Include to support strcasecmp with POSIX build */
#include <strings.h>


#endif  /*define USER_SETTINGS_H */

