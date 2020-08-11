#ifndef _RSA_SIGN_VERIFY__H
#define _RSA_SIGN_VERIFY__H

bool RSASign_Verify(const void *signed_data, int signed_data_len, const char* signature_base64, const char* publickey_base64);
bool RSASign_Verify(const void *signed_data, int signed_data_len, const unsigned char* signature, int signature_len, const unsigned char* publickey, int publickey_len);
bool RSASign_Verify(const unsigned char *signed_hash_20, const unsigned char* signature, int signature_len, const unsigned char* publickey_asn1, int publickey_asn1_len);

bool ReadObjectValue(const unsigned char* buf, int len, unsigned char* oid, int oid_len, const unsigned char*(*output), unsigned int* outlen);

#endif