#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <cstring>

#include <openssl/dh.h>
#include <openssl/sha.h>

#define DH_KEY_SIZE 96
#define SHA_DIGEST_LENGTH 20

static const unsigned char DHGenerator[1] = {2};
static const unsigned char DHPrime[] = {
    /* Well-known Group 1, 768-bit prime */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9,
    0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6,
    0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e,
    0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
    0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e,
    0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a,
    0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14,
    0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
    0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4,
    0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

class Crypto {
public:
    Crypto();
    ~Crypto();

    void DHInit();
    uint16_t dhCalculate(uint8_t *remote_key, uint8_t **sharedKey, uint16_t remote_key_length);
    int decodeBlob(uint8_t *blob, uint16_t blob_len, uint8_t *sharedkey, uint16_t sharedkey_len, uint8_t **encrypted);
    uint16_t decodeBlobSecondary(uint8_t **blob, uint8_t *username, uint8_t *deviceId, uint16_t blob_len, uint16_t username_len, uint16_t deviceId_len);
    char *getKey();
private:
    uint8_t *publicKey;
    uint16_t publicKey_length;
    char *publicKeyEncoded;
    char *username;
    DH *dhContext;
    SHA_CTX sha1Context;
};

#endif  // __CRYPTO_H__
