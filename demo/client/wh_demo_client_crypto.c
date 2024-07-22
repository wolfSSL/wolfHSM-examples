#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "wh_demo_client_crypto.h"
#include "wolfhsm/wh_error.h"

int wh_DemoClient_CryptoRsa(whClientContext* clientContext)
{
    int ret;
    int needEvict = 0;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    const char plainString[] = "The quick brown fox jumps over the lazy dog.";
    byte plainText[256];
    byte cipherText[256];
    RsaKey rsa[1];
    WC_RNG rng[1];

    /* set the plainText to the test string */
    strcpy((char*)plainText, plainString);

    /* initialize rng to make the rsa key */
    ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* make the rsa key */
    ret = wc_MakeRsaKey(rsa, 2048, 65537, rng);
    if (ret != 0) {
        printf("Failed to wc_MakeRsaKey %d\n", ret);
        goto exit;
    }
    needEvict = 1;

    /* encrypt the plaintext */
    ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString), cipherText,
        sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, ret, plainText, sizeof(plainText),
        rsa);
    if (ret < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        printf("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        printf("RSA Decryption matches originl plaintext\n");
exit:
    (void)wc_FreeRng(rng);
    if (needEvict) {
        ret = wh_Client_GetKeyIdRsa(rsa, &keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_GetKeyIdRsa %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoRsaImport(whClientContext* clientContext)
{
    int ret;
    int keyFd;
    int keySz;
    int needEvict = 0;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    char keyFile[] = "../../../demo/certs/ca-key.der";
    const char plainString[] = "The quick brown fox jumps over the lazy dog.";
    char keyLabel[] = "baby's first key";
    uint8_t keyBuf[2048];
    byte plainText[256];
    byte cipherText[256];
    RsaKey rsa[1];
    WC_RNG rng[1];

    /* set the plainText to the test string */
    strcpy((char*)plainText, plainString);

    /* initialize rng to encrypt with the rsa key */
    ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* open the RSA key */
    ret = keyFd = open(keyFile, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFile, ret);
        goto exit;
    }

    /* read the RSA key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFile, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    needEvict = 1;

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdRsa(rsa, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString), cipherText,
        sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, ret, plainText, sizeof(plainText),
        rsa);
    if (ret < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        printf("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        printf("RSA Decryption matches originl plaintext with imported key\n");
exit:
    (void)wc_FreeRng(rng);
    if (needEvict) {
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoCurve25519(whClientContext* clientContext)
{
    int ret;
    int needEvictPriv;
    int needEvictPub;
    word32 outLen;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];
    curve25519_key curve25519PrivateKey[1];
    /* public from the first shared secret's perspective, actually private */
    curve25519_key curve25519PublicKey[1];
    WC_RNG rng[1];

    /* initialize rng to make the cruve25519 keys */
    ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the keys */
    ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* generate the keys on the HSM */
    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    needEvictPriv = 1;

    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    needEvictPub = 1;

    /* generate shared secrets from both perspectives */
    outLen = sizeof(sharedOne);

    ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey,
        sharedOne, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey,
        sharedTwo, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* free the key structs */
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);

    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("CURVE25519 shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("CURVE25519 shared secrets match\n");
    }
exit:
    (void)wc_FreeRng(rng);
    if (needEvictPriv) {
        ret = wh_Client_GetKeyIdCurve25519(curve25519PrivateKey, &keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_GetKeyIdRsa %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (needEvictPub) {
        ret = wh_Client_GetKeyIdCurve25519(curve25519PublicKey, &keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_GetKeyIdRsa %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoCurve25519Import(whClientContext* clientContext)
{
    int ret;
    int keyFd;
    int keySz;
    word32 outLen;
    whKeyId keyIdPrivBob = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPubAlice = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPrivAlice = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPubBob = WOLFHSM_KEYID_ERASED;
    char privKeyFileBob[] = "../../../demo/certs/curve25519-private-bob.raw";
    char pubKeyFileAlice[] = "../../../demo/certs/curve25519-public-alice.raw";
    char privKeyFileAlice[] = "../../../demo/certs/curve25519-private-alice.raw";
    char pubKeyFileBob[] = "../../../demo/certs/curve25519-public-bob.raw";
    char keyLabel[] = "baby's first key";
    uint8_t keyBuf[256];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];
    curve25519_key curve25519PrivateKey[1];
    curve25519_key curve25519PublicKey[1];

    /* open the first private curve25519 key */
    ret = keyFd = open(privKeyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", privKeyFileBob, ret);
        goto exit;
    }

    /* read the first private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", privKeyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPrivBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the private key */
    ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdCurve25519(curve25519PrivateKey, keyIdPrivBob);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* open the first public curve25519 key */
    ret = keyFd = open(pubKeyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", pubKeyFileAlice, ret);
        goto exit;
    }

    /* read the first public key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", pubKeyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPubAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the public key */
    ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdCurve25519(curve25519PublicKey, keyIdPubAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* generate shared secret from perspective one */
    outLen = sizeof(sharedOne);
    ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey,
        sharedOne, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* free the key structs */
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);

    /* open the second private curve25519 key */
    ret = keyFd = open(privKeyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", privKeyFileAlice, ret);
        goto exit;
    }

    /* read the second private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", privKeyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPrivAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the private key */
    ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdCurve25519(curve25519PrivateKey, keyIdPrivAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* open the second public curve25519 key */
    ret = keyFd = open(pubKeyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", pubKeyFileBob, ret);
        goto exit;
    }

    /* read the second public key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", pubKeyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPubBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the public key */
    ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdCurve25519(curve25519PublicKey, keyIdPubBob);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* generate shared secret from perspective two */
    outLen = sizeof(sharedTwo);
    ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey,
        sharedTwo, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("CURVE25519 shared secrets don't match with imported keys\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("CURVE25519 shared secrets match with imported keys\n");
    }
exit:
    /* free the key structs */
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);

    if (keyIdPrivBob != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPrivBob);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPubAlice != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPubAlice);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPrivAlice != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPrivAlice);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPubBob != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPubBob);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoEcc(whClientContext* clientContext)
{
    int ret;
    int res;
    int needEvictPriv;
    int needEvictPub;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    word32 outLen;
    ecc_key eccPrivate[1];
    ecc_key eccPublic[1];
    WC_RNG rng[1];
    byte sharedOne[32];
    byte sharedTwo[32];
    const char plainMessage[] = "The quick brown fox jumps over the lazy dog.";
    byte message[sizeof(plainMessage)];
    byte signature[128];

    /* set the message to the test string */
    strcpy((char*)message, plainMessage);

    /* initialize rng to make the ecc keys */
    ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the keys */
    ret = wc_ecc_init_ex(eccPrivate, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_init_ex(eccPublic, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* make the keys */
    ret = wc_ecc_make_key(rng, 32, eccPrivate);
    if (ret != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }

    needEvictPriv = 1;

    ret = wc_ecc_make_key(rng, 32, eccPublic);
    if (ret != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }

    needEvictPub = 1;

    /* generate the shared secrets */
    outLen = 32;
    ret = wc_ecc_shared_secret(eccPrivate, eccPublic, (byte*)sharedOne,
        (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_shared_secret(eccPublic, eccPrivate, (byte*)sharedTwo,
        (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* compare the shared secrets */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("ECC shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("ECC shared secrets match\n");
    }

    /* sign the plaintext */
    outLen = sizeof(signature);
    ret = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
        (word32*)&outLen, rng, eccPrivate);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* verify the hash */
    ret = wc_ecc_verify_hash((void*)signature, outLen, (void*)message,
        sizeof(message), &res, eccPrivate);
    if (ret != 0) {
        printf("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        printf("ECC sign/verify successful\n");
    else {
        printf("ECC sign/verify failure\n");
        ret = -1;
        goto exit;
    }
exit:
    /* free the keys */
    wc_ecc_free(eccPrivate);
    wc_ecc_free(eccPublic);
    /* free rng */
    (void)wc_FreeRng(rng);
    /* evict the keys */
    if (needEvictPriv) {
        ret = wh_Client_GetKeyIdEcc(eccPrivate, &keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_GetKeyIdRsa %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (needEvictPub) {
        ret = wh_Client_GetKeyIdEcc(eccPublic, &keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_GetKeyIdRsa %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoEccImport(whClientContext* clientContext)
{
    int ret;
    int res;
    int keyFd;
    int keySz;
    whKeyId keyIdPrivBob = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPubAlice = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPrivAlice = WOLFHSM_KEYID_ERASED;
    whKeyId keyIdPubBob = WOLFHSM_KEYID_ERASED;
    word32 outLen;
    word32 sigLen;
    char privKeyFileBob[] = "../../../demo/certs/ecc-private-bob.raw";
    char pubKeyFileAlice[] = "../../../demo/certs/ecc-public-alice.raw";
    char privKeyFileAlice[] = "../../../demo/certs/ecc-private-alice.raw";
    char pubKeyFileBob[] = "../../../demo/certs/ecc-public-bob.raw";
    char keyLabel[] = "baby's first key";
    ecc_key eccPrivate[1];
    ecc_key eccPublic[1];
    WC_RNG rng[1];
    byte sharedOne[32];
    byte sharedTwo[32];
    const char plainMessage[] = "The quick brown fox jumps over the lazy dog.";
    byte message[sizeof(plainMessage)];
    byte signature[128];
    uint8_t keyBuf[256];

    /* set the message to the test string */
    strcpy((char*)message, plainMessage);

    /* initialize rng for signature signing */
    ret = wc_InitRng_ex(rng, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* open the first private ecc key */
    ret = keyFd = open(privKeyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", privKeyFileBob, ret);
        goto exit;
    }

    /* read the first private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", privKeyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPrivBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the private key */
    ret = wc_ecc_init_ex(eccPrivate, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* set the curveId by size */
    ret = wc_ecc_set_curve(eccPrivate, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdEcc(eccPrivate, keyIdPrivBob);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdEcc %d\n", ret);
        goto exit;
    }
    /* open the first public ecc key */
    ret = keyFd = open(pubKeyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", pubKeyFileAlice, ret);
        goto exit;
    }

    /* read the first public key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", pubKeyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPubAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the public key */
    ret = wc_ecc_init_ex(eccPublic, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* set the curveId by size */
    ret = wc_ecc_set_curve(eccPublic, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdEcc(eccPublic, keyIdPubAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdEcc %d\n", ret);
        goto exit;
    }

    /* generate the shared secret from the first perspective */
    outLen = 32;
    ret = wc_ecc_shared_secret(eccPrivate, eccPublic, (byte*)sharedOne,
        (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* sign the plaintext with the first private key */
    sigLen = sizeof(signature);
    ret = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
        (word32*)&sigLen, rng, eccPrivate);
    if (ret != 0) {
        printf("Failed to wc_ecc_sign_hash %d\n", ret);
        goto exit;
    }

    /* free the key structs */
    wc_ecc_free(eccPrivate);
    wc_ecc_free(eccPublic);

    /* open the second private ecc key */
    ret = keyFd = open(privKeyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", privKeyFileAlice, ret);
        goto exit;
    }

    /* read the second private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", privKeyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPrivAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the private key */
    ret = wc_ecc_init_ex(eccPrivate, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* set the curveId by size */
    ret = wc_ecc_set_curve(eccPrivate, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdEcc(eccPrivate, keyIdPrivAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdEcc %d\n", ret);
        goto exit;
    }

    /* open the second public ecc key */
    ret = keyFd = open(pubKeyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", pubKeyFileBob, ret);
        goto exit;
    }

    /* read the second public key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", pubKeyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        strlen(keyLabel), keyBuf, keySz, &keyIdPubBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the public key */
    ret = wc_ecc_init_ex(eccPublic, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* set the curveId by size */
    ret = wc_ecc_set_curve(eccPublic, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_SetKeyIdEcc(eccPublic, keyIdPubBob);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdEcc %d\n", ret);
        goto exit;
    }

    /* generated the shared secret from the second perspective */
    ret = wc_ecc_shared_secret(eccPrivate, eccPublic, (byte*)sharedTwo,
        (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* compare the shared secrets */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("ECC shared secrets don't match with imported keys\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("ECC shared secrets match with imported keys\n");
    }

    /* verify the hash */
    ret = wc_ecc_verify_hash((void*)signature, sigLen, (void*)message,
        sizeof(message), &res, eccPublic);
    if (ret != 0) {
        printf("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        printf("ECC sign/verify successful with imported keys\n");
    else {
        printf("ECC sign/verify failure with imported keys\n");
        ret = -1;
        goto exit;
    }
exit:
    /* free the key structs */
    wc_ecc_free(eccPrivate);
    wc_ecc_free(eccPublic);
    /* free rng */
    (void)wc_FreeRng(rng);
    if (keyIdPrivBob != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPrivBob);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPubAlice != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPubAlice);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPrivAlice != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPrivAlice);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    if (keyIdPubBob != WOLFHSM_KEYID_ERASED) {
        ret = wh_Client_KeyEvict(clientContext, keyIdPubBob);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoAesCbc(whClientContext* clientContext)
{
    int ret;
    Aes aes[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* set the key on the client side */
    ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }

    /* compare final and plain */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES CBC doesn't match after decryption\n");
        ret = -1;
        goto exit;
    }
    printf("AES CBC matches after decryption\n");
exit:
    return ret;
}

int wh_DemoClient_CryptoAesCbcImport(whClientContext* clientContext)
{
    int ret;
    int needEvict = 0;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    Aes aes[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char keyLabel[] = "baby's first key";
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_SetKeyIdAes(aes, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }

    /* compare final and plain */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES CBC doesn't match after decryption with imported key\n");
        ret = -1;
        goto exit;
    }
    printf("AES CBC matches after decryption with imported key\n");
exit:
    if (needEvict) {
        /* evict the key */
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoAesGcm(whClientContext* clientContext)
{
    int ret;
    Aes aes[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte iv[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authIn[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authTag[16];
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* set the key and iv on the client side */
    ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
        sizeof(iv), authTag, sizeof(authTag), authIn,
        sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
        sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare the finaltext to the plaintext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES GCM doesn't match after decryption\n");
        ret = -1;
        goto exit;
    }
    printf("AES GCM matches after decryption\n");
exit:
    return ret;
}

int wh_DemoClient_CryptoAesGcmImport(whClientContext* clientContext)
{
    int ret;
    int needEvict = 0;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    Aes aes[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char keyLabel[] = "baby's first key";
    byte iv[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authIn[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authTag[16];
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_SetKeyIdAes(aes, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* set the iv */
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
        sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
        sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare plaintext and finaltext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES GCM doesn't match after decryption with imported keys\n");
        ret = -1;
        goto exit;
    }
    printf("AES GCM matches after decryption with imported keys\n");
exit:
    if (needEvict) {
        /* evict the key from the cache */
        ret = wh_Client_KeyEvict(clientContext, keyId);
        if (ret != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", ret);
        }
    }
    return ret;
}

int wh_DemoClient_CryptoCmac(whClientContext* clientContext)
{
    int ret;
    word32 outLen;
    Cmac cmac[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char message[] = "hash and verify me!";
    byte tag[16];

    /* initialize the cmac struct and set the key */
    ret = wc_InitCmac_ex(cmac, key, sizeof(key), WC_CMAC_AES,
        NULL, NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, strlen(message));
    if (ret != 0) {
        printf("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        printf("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* verify the tag */
    ret = wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
        strlen(message), key, sizeof(key), NULL, WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("CMAC hash and verify failed %d\n", ret);
        goto exit;
    }

    printf("CMAC hash and verify succeeded\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}

int wh_DemoClient_CryptoCmacImport(whClientContext* clientContext)
{
    int ret;
    int needEvict = 0;
    word32 outLen;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    Cmac cmac[1];
    byte key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char keyLabel[] = "baby's first key";
    char message[] = "hash and verify me!";
    byte tag[16];

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL,
        WOLFHSM_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_SetKeyIdCmac(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, strlen(message));
    if (ret != 0) {
        printf("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        printf("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM again, cmac keys are evicted after wc_CmacFinal
     * is called */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
        sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_SetKeyIdCmac(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* verify the tag, note that for pre-cached keys we need to use the special
     * wolfHSM functions wh_Client_AesCmacGenerate and wh_Client_AesCmacVerify
     * when doing oneshot cmac generation or oneshot verifition, manual steps
     * can be done as above */
    ret = wh_Client_AesCmacVerify(cmac, tag, sizeof(tag), (byte*)message,
        strlen(message), keyId, NULL);
    if (ret != 0) {
        printf("CMAC hash and verify failed with imported key %d\n", ret);
        goto exit;
    }

    printf("CMAC hash and verify succeeded with imported key\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}
