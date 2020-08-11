/*
* PKCS #1 (RSA Encryption)
* Copyright (c) 2006-2009, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/

#ifndef PKCS1_H
#define PKCS1_H

#ifdef  __cplusplus
extern "C" {
#endif

int pkcs1_encrypt(int block_type, struct crypto_rsa_key *key, int use_private, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);
int pkcs1_v15_private_key_decrypt(struct crypto_rsa_key *key, const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen);
int pkcs1_decrypt_public_key(struct crypto_rsa_key *key, const unsigned char *crypt, unsigned int crypt_len, unsigned char *plain, unsigned int *plain_len);

#ifdef  __cplusplus
}
#endif

#endif /* PKCS1_H */