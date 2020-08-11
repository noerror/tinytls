#ifndef RSA_H
#define RSA_H

#ifdef  __cplusplus
extern "C" {
#endif

struct crypto_rsa_key* crypto_rsa_import_public_key(const unsigned char *buf, unsigned int len);
struct crypto_rsa_key* crypto_rsa_import_private_key(const unsigned char *buf, unsigned int len);

int crypto_rsa_exptmod(const unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int *outlen, struct crypto_rsa_key *key, int use_private);
void crypto_rsa_free(struct crypto_rsa_key *key);

unsigned int crypto_rsa_get_modulus_len(struct crypto_rsa_key *key);

#ifdef  __cplusplus
}
#endif


#endif /* RSA_H */