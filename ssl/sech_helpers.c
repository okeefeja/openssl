/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal data structures and prototypes for handling
 * stealthy Encrypted ClientHello (SECH)
 */
#ifndef OPENSSL_NO_ECH
#define SECH_SYMMETRIC_KEY_MAX_LENGTH 1024
// int sech_function_definition_to_find(void);
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/trace.h>

OSSL_LIB_CTX *libctx = NULL;
const char *propq = NULL;

char * unsafe_encrypt_aes128gcm(
    unsigned char * plain,
    int plain_len,
    unsigned char * somekey,
    int key_len,
    int * out_len)
{
    
    if (OSSL_TRACE_ENABLED(TLS)) {
        fprintf(stderr, "trace enabled\n");
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Debugging information\n");
        } OSSL_TRACE_END(TLS);
    }
    BIO * trace_out = BIO_new_fp(stderr, NULL);
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trace_out, "SECH: test trace BIO_printf\n");
    } OSSL_TRACE_END(TLS);
#ifdef  SECH_DEBUG
    fprintf(stderr, "SECH: debug enabled\n");
#endif//SECH_DEBUG
    unsigned char outbuf[1024];
    int outlen, tmplen;

    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char * iv = NULL; // {0,0,0,0,0,0,0,0,0,0,0,0};// NULL; // TODO generate iv securely
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER * cipher = NULL;

#ifdef  SECH_DEBUG
    BIO_dump_fp(stderr, plain, plain_len);
    BIO_dump_fp(stderr, somekey, key_len);
#endif//SECH_DEBUG

    ctx = EVP_CIPHER_CTX_new();
    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-128-GCM", propq)) == NULL) {
        fprintf(stderr, "SECH: unsafe error in EVP_CIPHER_fetch\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    if (!EVP_EncryptInit_ex2(ctx, cipher, somekey, iv, NULL)) {
        /* Error */
        fprintf(stderr, "SECH: unsafe error in EVP_EncryptInit_ex2\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if( !EVP_EncryptUpdate(
       ctx,
       outbuf,
       &outlen,
       plain,
       plain_len) )
    {
        fprintf(stderr, "SECH: encountered error in EVP_EncryptUpdate\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int iv_length = EVP_CIPHER_CTX_get_iv_length(ctx);
    fprintf(stderr, "SECH: iv length: %i\n", iv_length);
    // const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
    unsigned char updated_iv[iv_length];
    if(!EVP_CIPHER_CTX_get_updated_iv(ctx, updated_iv, iv_length)) {
        fprintf(stderr, "SECH: failed to get updated_iv\n");
    }
    BIO_dump_fp(stderr, updated_iv, iv_length);

    if( !EVP_EncryptFinal_ex(
          ctx, // EVP_CIPHER_CTX *ctx,
          outbuf + outlen,
          &tmplen) )
    {
        fprintf(stderr, "SECH: encountered error in EVP_EncryptFinal_ex\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    outlen += tmplen;
    fprintf(stderr, "SECH: outlen: %i\n", outlen);
    fprintf(stderr, "SECH: outbuf ptr: %p\n", (void*)outbuf);
    fprintf(stderr, "SECH: outbuf:\n");
    BIO_dump_fp(stderr, outbuf, outlen);
    char* ret = (char*)malloc(outlen + 1);
    if (ret == NULL) {
        fprintf(stderr, "SECH: failed to allocate memory\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(ret, outbuf, outlen);
    fprintf(stderr, "SECH: ret ptr: %p\n", (void*)ret);
    BIO_dump_fp(stderr, ret, outlen);
    fprintf(stderr, "SECH: finished symmetric encryption\n");
    *out_len = outlen;
    return ret;
}






char *unsafe_decrypt_aes128gcm(
    unsigned char *ciphertext,
    int ciphertext_len,
    unsigned char *somekey,
    int key_len,
    int *out_len)
{
    if (OSSL_TRACE_ENABLED(TLS)) {
        fprintf(stderr, "trace enabled\n");
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out, "Debugging information\n");
        } OSSL_TRACE_END(TLS);
    }
    BIO * trace_out = BIO_new_fp(stderr, NULL);
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trace_out, "SECH: test trace BIO_printf\n");
    } OSSL_TRACE_END(TLS);
#ifdef  SECH_DEBUG
    fprintf(stderr, "SECH: debug enabled\n");
#endif//SECH_DEBUG

    /*
     * Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char * iv = NULL; // {0,0,0,0,0,0,0,0,0,0,0,0};// NULL; // TODO generate iv securely
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER * cipher = NULL;

    unsigned char plaintext[1024];
    int len, plaintext_len;

#ifdef  SECH_DEBUG
    BIO_dump_fp(stderr, ciphertext, ciphertext_len);
    BIO_dump_fp(stderr, somekey, key_len);
#endif//SECH_DEBUG

    ctx = EVP_CIPHER_CTX_new();
    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "AES-128-GCM", propq)) == NULL) {
        fprintf(stderr, "SECH: unsafe error in EVP_CIPHER_fetch\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex2(ctx, cipher, somekey, iv, NULL)) {
        /* Error */
        fprintf(stderr, "SECH: unsafe error in EVP_DecryptInit_ex2\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if(!EVP_DecryptUpdate(
        ctx, 
        plaintext, 
        &len, 
        ciphertext, 
        ciphertext_len)) 
    {
        fprintf(stderr, "SECH: encountered error in EVP_DecryptUpdate\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    int iv_length = EVP_CIPHER_CTX_get_iv_length(ctx);
    fprintf(stderr, "SECH: iv length: %i\n", iv_length);
    // const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
    unsigned char updated_iv[iv_length];
    if(!EVP_CIPHER_CTX_get_updated_iv(ctx, updated_iv, iv_length)) {
        fprintf(stderr, "SECH: failed to get updated_iv\n");
    }
    BIO_dump_fp(stderr, updated_iv, iv_length);

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "SECH: encountered error in EVP_DecryptFinal_ex\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;
    fprintf(stderr, "SECH: outlen: %i\n", plaintext_len);
    fprintf(stderr, "SECH: outbuf ptr: %p\n", (void*)plaintext);
    fprintf(stderr, "SECH: outbuf:\n");
    BIO_dump_fp(stderr, plaintext, plaintext_len);
    char* ret = (char*)malloc(plaintext_len + 1);
    if (ret == NULL) {
        fprintf(stderr, "SECH: failed to allocate memory\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(ret, plaintext, plaintext_len);
    fprintf(stderr, "SECH: ret ptr: %p\n", (void*)ret);
    BIO_dump_fp(stderr, ret, plaintext_len);
    fprintf(stderr, "SECH: finished symmetric encryption\n");
    *out_len = plaintext_len;
    return ret;
}
#endif
