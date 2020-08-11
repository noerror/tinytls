#include "rsa_sign.h"
#include "base64.h"
#include <string.h>
#include <vector>
#include "pkcs1.h"
#include "rsa.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "asn1.h"

bool ReadObjectValue(const unsigned char* buf, int len, unsigned char* oid, int oid_len, const unsigned char*(* output), unsigned int* outlen)
{
	do
	{
		struct asn1_hdr hdr;

		if (asn1_get_next(buf, len, &hdr) < 0)
			return false;

		len = (buf + len) - (hdr.payload + hdr.length); // next
		buf = hdr.payload + hdr.length;

		if (hdr.tag == ASN1_TAG_SEQUENCE)
		{
			struct asn1_hdr child;
			if (asn1_get_next(hdr.payload, hdr.length, &child) >= 0 && child.classtype == ASN1_CLASS_UNIVERSAL && child.tag == ASN1_TAG_OID)
			{
				if (child.length == oid_len && !memcmp(child.payload, oid, oid_len))
				{
					if (asn1_get_next(buf, len, &hdr) >= 0)
					{
						*output = hdr.payload;
						*outlen = hdr.length;
						return true;
					}
				}
			}

			if (ReadObjectValue(hdr.payload, hdr.length, oid, oid_len, output, outlen) == true)
				return true;
		}
	} while (len > 0);
	return false;
}

bool RSASign_Verify(const unsigned char *signed_hash_20, const unsigned char* signature, int signature_len, const unsigned char* publickey_asn1, int publickey_asn1_len)
{
	/* Public Key file (PKCS#8)
	0000: 30 82 01 22                               ; SEQUENCE (122 바이트)
	0004:    30 0d                                  ; SEQUENCE (d 바이트) [AlgorithmIdentifier]
	0006:    |  06 09                               ; OBJECT_ID (9 바이트) [algorithm]
	0008:    |  |  2a 86 48 86 f7 0d 01 01  01      ; 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
	0011:    |  05 00                               ; NULL (0 바이트) [parameters]
	0013:    03 82 01 0f                            ; BIT_STRING (10f 바이트) [PublicKey]
	0017:       00
	0018:       30 82 01 0a                         ; SEQUENCE (10a 바이트)
	001c:          02 82 01 01                      ; INTEGER (101 바이트)
	0020:          |  00
	0021:          |  b5 fe e5 07 9f 39 a3 28  ec ee 85 60 ff e7 ea cc
	0031:          |  8c 0b af 9c af 82 83 d5  58 88 bd 1e 49 9d 7c bb
	0041:          |  44 80 30 2b 56 71 b9 a7  6d b9 7c 65 eb c6 5b 9e
	0051:          |  3c 02 6e 9c e0 16 02 a1  de 55 37 ff 0b 57 b1 6f
	0061:          |  d0 0a f0 d9 a4 56 c4 1a  ad 97 d7 a7 6e 6f ef 37
	0071:          |  19 f0 4f d0 b8 83 ae af  ac 30 6e 68 23 05 a2 b7
	0081:          |  ca 0d 4c 10 03 5b 80 66  2d 94 97 71 93 d5 74 6e
	0091:          |  bf 01 7e 67 b7 94 95 41  e2 27 a5 66 e4 dc a0 9f
	00a1:          |  e5 6c 9b 72 b8 cb 5c f2  68 21 a5 d2 c1 8b 25 65
	00b1:          |  9f bb 07 ea 64 5d bc 47  6a df 1e 01 eb 05 c4 3d
	00c1:          |  87 9d 10 7c 3a bf 43 11  93 db fb 60 ed 2d 42 da
	00d1:          |  49 8f d4 cc 60 64 0d a0  7a fe a7 35 dd 56 aa 64
	00e1:          |  b4 25 05 ba ae fb 1e 23  51 b8 a1 07 bd 41 94 f2
	00f1:          |  ed 1d a3 50 1b e5 e4 d1  e5 65 6e ca df e8 7e 81
	0101:          |  d1 36 51 34 d2 9e 6c 98  bc 4e f4 43 a4 a6 08 58
	0111:          |  e3 e6 3e 72 94 57 69 de  1f 2a 66 ec b7 b7 1e 9f
	0121:          02 03                            ; INTEGER (3 바이트)
	0123:             01 00 01
	*/

	/*
     * PKCS #1, 7.1:
     * RSAPublicKey ::= SEQUENCE {
     *     modulus INTEGER, -- n
     *     publicExponent INTEGER -- e 
     * }
    */


	struct crypto_rsa_key * key;

	const unsigned char *public_key;
	unsigned int key_len = 0;
	static unsigned char _RSA_SIGN[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
	if (ReadObjectValue(publickey_asn1, publickey_asn1_len, _RSA_SIGN, sizeof(_RSA_SIGN), &public_key, &key_len)) // Public Key file (PKCS#8)
	{
		if (public_key[0] == 0) // certificate
			key = crypto_rsa_import_public_key(&public_key[1], key_len-1); // certificate
		else
			key = crypto_rsa_import_public_key(public_key, key_len);
	}
	else
	{
		key = crypto_rsa_import_public_key(publickey_asn1, publickey_asn1_len); // RSA Public Key file (PKCS#1) : certificate
	}
	if (key == NULL)
		return false;

	unsigned char hash_decoded[256];
	unsigned int hash_decoded_len = 256;
	if (pkcs1_decrypt_public_key(key, signature, signature_len, hash_decoded, &hash_decoded_len) < 0)
	{
		crypto_rsa_free(key);
		return false;
	}
/*
	0000: 30 21                                     ; SEQUENCE (21 바이트)
	0002:    30 09                                  ; SEQUENCE (9 바이트)
	0004:    |  06 05                               ; OBJECT_ID (5 바이트)
	0006:    |  |  2b 0e 03 02 1a                   ; 1.3.14.3.2.26 sha1 (sha1NoSign)
	000b:    |  05 00                               ; NULL (0 바이트)
	000d:    04 14                                  ; OCTET_STRING (14 바이트)
	000f:       13 ea 3e 9e 98 1d 44 d3  ca 00 06 76 9e 46 d3 53  ; ..>...D....v.F.S
	001f:       f4 1f 14 2c                                       ; ...,
*/
	static unsigned char _SHA1NOSIGN[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
	const unsigned char* hash_extract = NULL;
	unsigned int hash_extract_len;
	if (ReadObjectValue(hash_decoded, hash_decoded_len, _SHA1NOSIGN, sizeof(_SHA1NOSIGN), &hash_extract, &hash_extract_len))
	{
		if (hash_extract_len == 20 && !memcmp(hash_extract, signed_hash_20, 20))
		{
			crypto_rsa_free(key);
			return true;
		}
	}

	crypto_rsa_free(key);
	return false;
}

bool RSASign_Verify(const void *signed_data, int signed_data_len, const unsigned char* signature, int signature_len, const unsigned char* publickey, int publickey_len)
{
	unsigned char sha1hash[20];
	Sha1((unsigned char*)signed_data, signed_data_len, sha1hash);

	return RSASign_Verify(sha1hash, signature, signature_len, publickey, publickey_len);
}

bool RSASign_Verify(const void *signed_data, int signed_data_len, const char* signature_base64, const char* publickey_base64)
{
	std::vector <unsigned char> key_stream = Base64Decode(publickey_base64);
	std::vector <unsigned char> signature_stream = Base64Decode(signature_base64);

	return RSASign_Verify(signed_data, signed_data_len, &signature_stream[0], (int)signature_stream.size(), &key_stream[0], (int)key_stream.size());
}

/*
void main()
{
	const char* _publickey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtf7lB585oyjs7oVg/+fqzIwLr5yvgoPVWIi9HkmdfLtEgDArVnG5p225fGXrxluePAJunOAWAqHeVTf/C1exb9AK8NmkVsQarZfXp25v7zcZ8E/QuIOur6wwbmgjBaK3yg1MEANbgGYtlJdxk9V0br8Bfme3lJVB4ielZuTcoJ/lbJtyuMtc8mghpdLBiyVln7sH6mRdvEdq3x4B6wXEPYedEHw6v0MRk9v7YO0tQtpJj9TMYGQNoHr+pzXdVqpktCUFuq77HiNRuKEHvUGU8u0do1Ab5eTR5WVuyt/ofoHRNlE00p5smLxO9EOkpghY4+Y+cpRXad4fKmbst7cenwIDAQAB";
	const char _signed_data[] = "{\"packageName\":\"com.ohcoco.tilly\",\"productId\":\"gem_package_30\",\"purchaseTime\":1487143702104,\"purchaseState\":0,\"developerPayload\":\"noerror\",\"purchaseToken\":\"flknnioeompcfhffdbfehphm.AO-J1Ow7uDg36hLFSaMpuEDlIXz3kaOFkZ0kqKrz5li7fIBVbaVULk-MCRHQgQfKrH12vPGxJbwuvnPys5DfeeKFLPn2uGnp18MGjRSRTb9scx-omojQz1t0tekEcPTKLShVnXSKNiPI\"}";
	const char _signature[] = "esM+64QegdokwZYqrcb5hZgSXW9cmTR8l46LJYZKq3DO0BxQQzviIoqxHkwGfmGayzR3lbEDRp67ziqos8iufxo5oVsFS6Q0ELcpOJvnkStLThU9qzOTYCQr8J4wJH7U3bU75w4wrmQ0qMmqXBgDXk7N2Oru3As7iNKlbNT69sqG4Qc7h+AFGdZTAZzf3+o7fsA4fMwlus2t99g3Jbx+Xvn6nwzw2oGrbha12RdrPloYwski6cslr0i10+PYkilPjlWaJXBFdDw\\/i\\/i+6n6SbyqUTfr5\\/eOSEcdvreSyevKjeWos8HCoel\\/OvukufA2uY1dSho4HsCWQ8b1F\\/DxiQQ==";

	RSASign_Verify(_signed_data, sizeof(_signed_data) - 1, _signature, _publickey);
}
*/