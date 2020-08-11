#ifndef _MD5_H
#define _MD5_H

#ifdef  __cplusplus
extern "C" {
#endif

void MD5(const unsigned char *initial_msg, int initial_len, unsigned char* output_hash_16);
void HMAC_MD5(const unsigned char* key, int key_len, const unsigned char* message, int msg_len, unsigned char* output_hash_16);

void MD5_Init(unsigned char* output_hash_16);
void MD5_Update(unsigned char* output_hash_16, const void *msg);
void MD5_Final(unsigned char* output_hash_16, const void* msg, int msg_len, int total_length);

#ifdef  __cplusplus
}
#endif

#endif