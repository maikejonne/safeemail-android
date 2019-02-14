#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "include/secp256k1.h"
#include "org_bitcoin_NativeBlowfish.h"
#include "include/blowfish.h"

uint8_t* output = NULL;

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeBlowfish_blowfish_1encrypt
        (JNIEnv* env , jclass classObject, jobject byteBufferObject, jlong pw_l, jlong data_l)
{
    unsigned char* key = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    uint8_t* data= key + pw_l;

    BLOWFISH_CTX ctx;
    Blowfish_Init(&ctx, key, pw_l);

    uint32_t message_left = 1;
    uint32_t message_right = 2;

    uint8_t padding_length = data_l % sizeof(uint64_t);
    if (padding_length != 0) {
        padding_length = sizeof(uint64_t) - padding_length;
    }
    uint32_t outputLen = data_l + padding_length;
    output = malloc(outputLen + 4);
    uint8_t* p = output;

    uint32_t rDL = (uint32_t)data_l;
    memcpy(output, &rDL, 4);
    output += 4;

    int block_len = 0;

    while (outputLen) {
        message_left = message_right = 0UL;

        /* crack the message string into a 64-bit block (ok, really two 32-bit blocks); pad with zeros if necessary */
        for (block_len = 0; block_len < 4; block_len++) {
            message_left = message_left << 8;
            if (outputLen) {
                message_left += *data++;
                outputLen--;
            } else message_left += 0;
        }
        for (block_len = 0; block_len < 4; block_len++) {
            message_right = message_right << 8;
            if (outputLen) {
                message_right += *data++;
                outputLen--;
            } else message_right += 0;
        }
        Blowfish_Encrypt(&ctx, &message_left, &message_right);
        /* save the results for decryption below */
        *output++ = (uint8_t)(message_left >> 24);
        *output++ = (uint8_t)(message_left >> 16);
        *output++ = (uint8_t)(message_left >> 8);
        *output++ = (uint8_t)message_left;
        *output++ = (uint8_t)(message_right >> 24);
        *output++ = (uint8_t)(message_right >> 16);
        *output++ = (uint8_t)(message_right >> 8);
        *output++ = (uint8_t)message_right;
    }

    outputLen =  data_l + padding_length + 4;
    output = p;

    jobjectArray retArray;
    jbyteArray pubkeyArray, intsByteArray;
    uint32_t intsarray[2];

    intsarray[0] = outputLen;
    intsarray[1] = 1;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    pubkeyArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, pubkeyArray, 0, outputLen, (jbyte*)output);
    (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

    intsByteArray = (*env)->NewByteArray(env, 8);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 8, (jbyte *)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;
    free(output);
    output = NULL;
    return retArray;
}

unsigned int read24 (unsigned char *ptr)
{
    unsigned char b0;
    unsigned char b1;
    unsigned char b2;
    unsigned char b3;

    b0 = *ptr++;  /* 00001111000001110000001100000001 */
    b1 = *ptr++;  /* b0      b1      b2      b3       */
    b2 = *ptr++;  /* b3      b2      b1      b0       */
    b3 = *ptr;    /* 00000001000000110000011100001111 */

    return ((b0 & 0x000000ffU)         |
            ((b1 << 8 )  & 0x0000ff00U) |
            ((b2 << 16)  & 0x00ff0000U) |
            ((b3 << 24)  & 0xff000000U));
}

SECP256K1_API jobjectArray JNICALL Java_org_bitcoin_NativeBlowfish_blowfish_1decrypt
        (JNIEnv* env , jclass classObject, jobject byteBufferObject, jlong pw_l, jlong data_l)
{
    unsigned char* key = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
    uint8_t* ciphertext_string= key + pw_l;

    BLOWFISH_CTX ctx;
    Blowfish_Init(&ctx, key, pw_l);

    uint32_t message_left = 1;
    uint32_t message_right = 2;
    int block_len = 0;
    uint32_t ciphertext_len = data_l -4;

    output = malloc(ciphertext_len);
    uint8_t* p = output;
    uint8_t* pCiphertext = ciphertext_string;

    ciphertext_string +=4;
    while(ciphertext_len)
    {
        message_left = message_right = 0UL;

        for (block_len = 0; block_len < 4; block_len++)
        {
            message_left = message_left << 8;
            message_left += *ciphertext_string++;
            if (ciphertext_len)
                ciphertext_len--;
        }
        for (block_len = 0; block_len < 4; block_len++)
        {
            message_right = message_right << 8;
            message_right += *ciphertext_string++;
            if (ciphertext_len)
                ciphertext_len--;
        }

        Blowfish_Decrypt(&ctx, &message_left, &message_right);
        *output++ = (uint8_t)(message_left >> 24);
        *output++ = (uint8_t)(message_left >> 16);
        *output++ = (uint8_t)(message_left >> 8);
        *output++ = (uint8_t)message_left;
        *output++ = (uint8_t)(message_right >> 24);
        *output++ = (uint8_t)(message_right >> 16);
        *output++ = (uint8_t)(message_right >> 8);
        *output++ = (uint8_t)message_right;
    }
    output = p;
    uint32_t outputLen = read24(pCiphertext);

    uint32_t ret = 1;
    if(outputLen > data_l){
        outputLen = 0;
        ret = 0;
    }

    jobjectArray retArray;
    jbyteArray pubkeyArray, intsByteArray;
    uint32_t intsarray[2];

    intsarray[0] = outputLen;
    intsarray[1] = ret;

    retArray = (*env)->NewObjectArray(env, 2,
                                      (*env)->FindClass(env, "[B"),
                                      (*env)->NewByteArray(env, 1));

    pubkeyArray = (*env)->NewByteArray(env, outputLen);
    (*env)->SetByteArrayRegion(env, pubkeyArray, 0, outputLen, (jbyte*)output);
    (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

    intsByteArray = (*env)->NewByteArray(env, 8);
    (*env)->SetByteArrayRegion(env, intsByteArray, 0, 8, (jbyte *)intsarray);
    (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

    (void)classObject;
    free(output);
    output = NULL;

    return retArray;
}