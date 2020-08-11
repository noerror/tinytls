#ifndef _SHA1_H
#define _SHA1_H

#ifdef  __cplusplus
extern "C" {
#endif

void Sha1(const unsigned char* data, int len, unsigned char* output_hash_20);
void HMAC_Sha1(const unsigned char* key, int key_len, unsigned char* message, int msg_len, unsigned char* output_hash_20);

void Sha1_Init(unsigned char* output_hash_20);
void Sha1_Update(unsigned char* output_hash_20, const void *msg);
void Sha1_Final(unsigned char* output_hash_20, const void* msg, int msg_len, int total_length);

#ifdef  __cplusplus
}
#endif

#endif