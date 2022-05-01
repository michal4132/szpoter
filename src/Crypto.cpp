#include "Crypto.h"
#include "Log.h"

#include <openssl/modes.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// TODO

void generateVectorWithRandomData(uint8_t **randomData, size_t length){
    *randomData = (uint8_t *) malloc(length);
    if(RAND_bytes(*randomData, length) == 0){
        LOG(debug, "Error generating random");
    }
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text=(*bufferPtr).data;

    return (0); //success
}

Crypto::Crypto() {

}

Crypto::~Crypto() {
    free(publicKeyEncoded);
}

void Crypto::DHInit(){
    // init dh
    dhContext = DH_new();

    DH_set0_pqg(dhContext, BN_bin2bn(DHPrime, DH_KEY_SIZE, NULL), NULL, BN_bin2bn(DHGenerator, 1, NULL));

    // generate public and private keys
    BIGNUM *public_key = BN_new();
    DH_generate_key(dhContext);

    int len = BN_num_bytes(DH_get0_pub_key(dhContext));
    publicKey = (uint8_t*)malloc(len);
    len = BN_bn2bin(DH_get0_pub_key(dhContext), (uint8_t*)publicKey);
    publicKey_length = len;

    publicKeyEncoded = (char*)malloc(len);

    Base64Encode(publicKey, len, &publicKeyEncoded);
}

char *Crypto::getKey() {
    return publicKeyEncoded;
}

// calculate shared key from client public
uint16_t Crypto::dhCalculate(uint8_t *remote_key, uint8_t **sharedKey, uint16_t remote_key_length) {
    unsigned char *out_key = (uint8_t*)malloc(DH_size(dhContext));
    BIGNUM *pubKey = BN_new();
    BN_bin2bn(remote_key, DH_KEY_SIZE, pubKey);

    uint16_t keyLen = DH_compute_key(out_key, pubKey, dhContext);

    *sharedKey = (uint8_t*)out_key;

    BN_free(pubKey);
    return keyLen;
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input);
    size_t padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

void Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message);
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer

    *length = BIO_read(bio, *buffer, decodeLen);
    BIO_free_all(bio);
}

uint32_t readBlobInt(uint8_t *data, uint16_t *skip){
    uint8_t lo = data[*skip];
    if ((int)(lo & 0x80) == 0) {
        (*skip) += 1;
        return lo;
    }

    uint8_t hi = data[(*skip) + 1];
    (*skip) += 2;

    return (uint32_t)((lo & 0x7f) | (hi << 7));
}

void sha1HMAC(uint8_t *inputkey, uint16_t inputkey_len, uint8_t *message, uint16_t message_len, uint8_t *digest){
//  unsigned char hash[20];
    HMAC_CTX *hmacContext = HMAC_CTX_new();
    HMAC_Init_ex(hmacContext, inputkey, inputkey_len, EVP_sha1(), NULL);
    HMAC_Update(hmacContext, message, message_len);

    unsigned int resLen = 0;
    HMAC_Final(hmacContext, digest, &resLen);

    HMAC_CTX_free(hmacContext);
}

void aesCTRXcrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint16_t key_len, uint16_t iv_len, uint16_t data_len){
    AES_KEY cryptoKey;

    AES_set_encrypt_key(key, 128, &cryptoKey);

    unsigned char ecountBuf[16] = {0};
    unsigned int offsetInBlock = 0;

    CRYPTO_ctr128_encrypt(
        data,
        data,
        data_len,
        &cryptoKey,
        iv,
        ecountBuf,
        &offsetInBlock,
        (block128_f)AES_encrypt);

}

void aesECBdecrypt(uint8_t *key, uint8_t **data, uint16_t key_len, uint16_t data_len){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, *(data), &len, *data, data_len);
    EVP_DecryptFinal_ex(ctx, (*data) + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

int Crypto::decodeBlob(uint8_t *blob, uint16_t blob_len, uint8_t *sharedkey, uint16_t sharedkey_len, uint8_t **encrypted){
    uint8_t *iv = (uint8_t*)malloc(16);
    uint16_t encrypted_len = blob_len - (16+20);
    *encrypted = (uint8_t*)malloc(encrypted_len);
    uint8_t *checksum = (uint8_t*)malloc(20);

    int enc_counter = 0;
    int checksum_counter = 0;


    printf("blobLen: %d\n", blob_len);
    printf("checksum:\n");
    for (int i = 0; i < blob_len; i++) {
        if (i < 16) {
            iv[i] = blob[i];
        }
        if(i >= 16 && i < (blob_len-20)){
            (*encrypted)[enc_counter++] = blob[i];
        }
        if(i >= (blob_len-20)){
            checksum[checksum_counter++] = blob[i];
            printf("%d ", blob[i]);
        }
    }
    printf("\n");

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, sharedkey, sharedkey_len);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &sha1Context);
    uint8_t *baseKey = (uint8_t*)malloc(16);

    printf("BaseKey: \n");
    for(int i = 0; i < 16; i++){
        baseKey[i] = hash[i];
        printf("%d ", baseKey[i]);
    }
    printf("\n");

    char checksumMessage[] = "checksum";
    uint8_t *checksumKey = (uint8_t*)malloc(SHA_DIGEST_LENGTH);
    sha1HMAC(baseKey, 16, (uint8_t*)checksumMessage, strlen(checksumMessage), checksumKey); // key_len = 20

    char encryptionMessage[] = "encryption";
    uint8_t *encryptionKeyFull = (uint8_t*)malloc(SHA_DIGEST_LENGTH);
    sha1HMAC(baseKey, 16, (uint8_t*)encryptionMessage, strlen(encryptionMessage), encryptionKeyFull);

    uint8_t *mac = (uint8_t *) malloc(SHA_DIGEST_LENGTH);
    sha1HMAC(checksumKey, SHA_DIGEST_LENGTH, *encrypted, blob_len - (16+SHA_DIGEST_LENGTH), mac);

    // check if mac matches checksum
    for (uint8_t i = 0; i < 20; i++) {
        if (mac[i] != checksum[i]) {
            printf("Mac doesn't match!\n");
            return 0;
        }
    }

    printf("MAC:\n");
    for(int i = 0; i < 20; i++){
        printf("%d ", mac[i]);
    }
    printf("\n");

    printf("Encryption key:\n");
    uint8_t *encryptionKey = (uint8_t*)malloc(16);
    for (int i = 0; i < 16; i++) {
        encryptionKey[i] = encryptionKeyFull[i];
        printf("%d ", encryptionKey[i]);
    }
    printf("\n");

    aesCTRXcrypt(encryptionKey, iv, *encrypted, 16, 16, encrypted_len);

    return encrypted_len;
}

uint16_t Crypto::decodeBlobSecondary(uint8_t **blob, uint8_t *username, uint8_t *deviceId, uint16_t blob_len, uint16_t username_len, uint16_t deviceId_len){
    unsigned char *blobBytes = (unsigned char *) malloc(blob_len);

    size_t keyLen;
    Base64Decode((char *) *blob, &blobBytes, &keyLen);

    if (keyLen == 0) {
        printf("Blob invalid\n");
        return 0;
    }

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, deviceId, deviceId_len);

    unsigned char secret[SHA_DIGEST_LENGTH];
    SHA1_Final(secret, &sha1Context);

    uint8_t pkBaseKey[20];
    PKCS5_PBKDF2_HMAC_SHA1((const char*) secret, sizeof(secret), username, username_len, 256, 20, pkBaseKey);

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, pkBaseKey, 20);

    unsigned char baseKeyHashed[SHA_DIGEST_LENGTH + 4];
    SHA1_Final(baseKeyHashed, &sha1Context);

    baseKeyHashed[20] = 0x00;
    baseKeyHashed[21] = 0x00;
    baseKeyHashed[22] = 0x00;
    baseKeyHashed[23] = 0x14;

    aesECBdecrypt(baseKeyHashed, &blobBytes, 24, keyLen);

    uint16_t len = keyLen;

    for (uint16_t i = 0; i < len; i++) {
        blobBytes[len - i - 1] ^= blobBytes[len - i - 17];
    }

    printf("after decrypt:\n");
    for (uint16_t i = 0; i < keyLen; i++) {
        printf("[%c:%d] ", blobBytes[i], blobBytes[i]);
    }
    printf("\n");

    *blob = blobBytes;
    return keyLen;
}

char *keyValuePair(char **input) {
    return strsep(input, "&");
}
char *extractKey(char **keyValue) {
    char *key = strsep(keyValue, "=");
    return key;
}

int ishex(int x) {
    return (x >= '0' && x <= '9') ||
        (x >= 'a' && x <= 'f') ||
        (x >= 'A' && x <= 'F');
}

int decode(const char *s, char *dec)
{
    char *o;
    const char *end = s + strlen(s);
    int c;

    for (o = dec; s <= end; o++) {
        c = *s++;
        if (c == '+') c = ' ';
        else if (c == '%' && (	!ishex(*s++)	||
                    !ishex(*s++)	||
                    !sscanf(s - 2, "%2x", &c)))
            return -1;

        if (dec) *o = c;
    }

    return o - dec;
}

// int decode_user_auth_request(int connection_fd, char *http, uint16_t http_len){
//     uint8_t *blobString;
//     uint8_t *deviceName;
//     uint8_t *clientKeyString;
//
//     char *in = strdup(http); // shit 1
//     char out[strlen(in)+1]; // shit 2
//     decode(in, out); // unescape url
//     char *input = strdup(out); // shit 3
//
//     printf("--------------------------------------------------------\n");
//
//     for (char *key; (key = keyValuePair(&input)); ) {
//         char *value = key;
//         extractKey(&value);
//         if(strcmp(key, "action") == 0 && strcmp(value, "addUser") == 0){
//           printf("Add user\n");
//         }
//
//         if(strcmp(key, "userName") == 0){
//           username = (uint8_t*)malloc(strlen(value)+1);
//           strcpy(username, value);
//         }
//         if(strcmp(key, "blob") == 0){
//           blobString = (uint8_t*)malloc(strlen(value)+1);
//           strcpy(blobString, value);
//         }
//         if(strcmp(key, "clientKey") == 0){
//           clientKeyString = (uint8_t*)malloc(strlen(value)+1);
//           strcpy(clientKeyString, value);
//         }
//         if(strcmp(key, "deviceName") == 0){
//           deviceName = (uint8_t*)malloc(strlen(value)+1);
//           strcpy(deviceName, value);
//         }
//     }
//
//     unsigned char *clientKeyBytes = malloc(strlen(clientKeyString));
//     unsigned char *blobBytes = malloc(strlen(blobString));
//
//     size_t keyLen;
//     Base64Decode(clientKeyString, &clientKeyBytes, &keyLen);
//     size_t blobLen;
//     Base64Decode(blobString, &blobBytes, &blobLen);
//
//     uint8_t *sharedKey;
//
//     dhCalculate(clientKeyBytes, &sharedKey, keyLen);
//
//     uint8_t *partDecoded;
//     uint16_t partDecoded_len = decodeBlob(blobBytes, blobLen, sharedKey, keyLen, &partDecoded);
//     if(partDecoded_len == 0){
//       return 0;
//     }
//
//     char *deviceId = "162137fd329622137a14901634264e6f332e2422";
//     char *sys_info = "cspot";
//     char *version_string = "cspot-1.0";
//     uint16_t loginData_len = decodeBlobSecondary(&partDecoded, username, deviceId, partDecoded_len, strlen(username), strlen(deviceId));
//     if(loginData_len == 0){
//       return 0;
//     }
//     printf("Second stage out len: %d\n", loginData_len);
//
//     uint16_t skipPos = 1;
//     skipPos+= readBlobInt(partDecoded, &skipPos); // skip position by length of username
//     skipPos+=1;
//     printf("auth type: %d\n", readBlobInt(partDecoded, &skipPos)); // type of auth
//     skipPos+=1;
//     uint16_t authBlob_len = readBlobInt(partDecoded, &skipPos); // length of auth blob
//     printf("auth size: %d\n", authBlob_len);
//
//     uint8_t *authBlob = malloc(authBlob_len);
//     uint16_t pos = 0;
//     for(uint16_t i = skipPos; i < (skipPos+authBlob_len); i++){
//       authBlob[pos++] = partDecoded[i];
//     }
// //    protoAuth(username, authBlob, sys_info, deviceId, version_string, strlen(username), authBlob_len, strlen(sys_info), strlen(deviceId), strlen(version_string));
// //--------------------------------------
// //  PROTO ASSEMBLY
//
//   PB pb_username, pb_blob, pb_sys_info, pb_device_id, pb_version_string, pb_auth_type, pb_cpu_family, pb_os;
//   PB_encode_string(&pb_username, 0xA, username, strlen(username));
//   PB_encode_string(&pb_blob, 0x1E, authBlob, authBlob_len);
//   PB_encode_string(&pb_sys_info, 0x5A, sys_info, strlen(sys_info));
//   PB_encode_string(&pb_device_id, 0x64, deviceId, strlen(deviceId));
//   PB_encode_string(&pb_version_string, 0x46, version_string, strlen(version_string));
//   PB_encode_enum(&pb_auth_type, 0x14, 0x1);
//   PB_encode_enum(&pb_cpu_family, 0xA, 0x0);
//   PB_encode_enum(&pb_os, 0x3C, 0x0);
//
//   // login credentials group
//   PB pb_login_credentials = PB_new();
//   PB_add(&pb_login_credentials, &pb_username);
//   PB_add(&pb_login_credentials, &pb_auth_type);
//   PB_add(&pb_login_credentials, &pb_blob);
//   PB_encode_group(&pb_login_credentials, 0xA);
//
//   //system info group
//   PB pb_system_info = PB_new();
//   PB_add(&pb_system_info, &pb_cpu_family);
//   PB_add(&pb_system_info, &pb_os);
//   PB_add(&pb_system_info, &pb_sys_info);
//   PB_add(&pb_system_info, &pb_device_id);
//   PB_encode_group(&pb_system_info, 0x32);
//
//   // merge
//   PB pb_output = PB_new();
//   PB_add(&pb_output, &pb_login_credentials);
//   PB_add(&pb_output, &pb_system_info);
//   PB_add(&pb_output, &pb_version_string);
//
//   printf("Proto: \n");
//   for(uint16_t i = 0; i < pb_output.len; i++){
//     printf("%02X", pb_output.data[i]);
//   }
//   printf("\n");
//
// //-------------------------------------
//
//   shannonSendPacket(connection_fd, pb_output.data, pb_output.len, LOGIN_REQUEST_COMMAND);
//
//   uint8_t *recv_packet;
//   uint16_t recv_len = shannonRecvPacket(connection_fd, &recv_packet);
//
//   free(partDecoded);
//   free(input);
//   free(in);
//   printf("---------------------------------------------------------\n");
//
//   if(recv_packet[0] == 0xAC){
//     printf("Authentication complete\n");
//     return 1;
//   }
//   return 0;
// }
