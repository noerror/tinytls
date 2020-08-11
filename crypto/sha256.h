#ifndef _SHA256_H
#define _SHA256_H

#ifdef  __cplusplus
extern "C" {
#endif

void Sha256(const unsigned char* data, int len, unsigned char* output32);
void HMAC_Sha256(const unsigned char* key, int key_len, unsigned char* message, int msg_len, unsigned char* output_hash_32);

#ifdef  __cplusplus
}
#endif

#endif