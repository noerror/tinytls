#include "tls.h"
#include <string.h>
#include <string>
#include "sha1.h"
#include "base64.h"
#include "md5.h"
#include "rsa.h"
#include "rijndael.h"
#include "rsa_sign.h"
#include <stdlib.h>

#pragma pack(1)
struct TLSHEADER {
	unsigned char contenttype; // change_cipher_spec(20), alert(21), handshake(22), application_data(23), (255)
	unsigned char version_major;
	unsigned char version_minor;
	unsigned char length[2];
};

struct HANDSHAKE {
	unsigned char msg_type; // hello_request(0), client_hello(1), server_hello(2), certificate(11), server_key_exchange(12), certificate_request(13), server_hello_done(14),
	// certificate_verify(15), client_key_exchange(16), finished(20), (255)
	unsigned char length[3];
};
#pragma pack()

inline unsigned long convert_little_endian(const unsigned char* p, int count)
{
	unsigned long v = 0;
	for (int i = 0; i < count; i++)
		v |= p[i] << ((count - 1 - i) * 8);
	return v;
}

CTLS::CTLS()
{
	m_PublicKey = NULL;
	Reset();
}

void CTLS::Reset()
{
	if (m_PublicKey != NULL)
	{
		crypto_rsa_free(m_PublicKey);
		m_PublicKey = NULL;
	}

	MD5_Init(m_HashshakeMD5);
	Sha1_Init(m_HashshakeSHA);

	m_HandshakeMessageLen = 0;

	memset(m_ServerSeq, 0, sizeof(m_ServerSeq));
	memset(m_ClientSeq, 0, sizeof(m_ClientSeq));

	memset(m_SessionID, 0, sizeof(m_SessionID));
	memset(m_MasterSecret, 0, sizeof(m_MasterSecret));

	m_Mode = _HANDSHAKE;
	m_Offset = 0;
	m_ChangeCiperSpec = 0;
	m_ServerSide = true;
	m_Version = 0x302;
}

int CTLS::OnRecv(const void* ptr, int len)
{
	if (m_Mode == _ERROR)
		return -1;

	const unsigned char* buff = (const unsigned char*)ptr;
	int off = 0;

	for (; off < len;)
	{
		if (len - off < 5)
			break;

		TLSHEADER* h = (TLSHEADER*)&buff[off];
		int h_length = convert_little_endian(h->length, 2);
		if (h_length + 5 > len - off)
			break;
		if (h->contenttype == 22) // handshake(22)
		{
			//m_Version = h->version_minor == 1 ? 0x301 : 302;

			if (m_Mode == _SECURE_CONNECTED)
			{
				unsigned char result[1024];
#ifdef _DEBUG
				_ASSERT(h_length <= sizeof(result));
#endif
				if (h_length > sizeof(result))
				{
					m_Mode = _ERROR;
					return -1;
				}

				m_ClientSecure.Decrypt((char*)&h[1], (char*)result, h_length, CRijndael::CBC);
				int iv_len = m_Version == 0x302 ? 16 : 0;
				if (TLS_Handshake(&result[iv_len], h_length - iv_len) == false)
				{
					m_Mode = _ERROR;
#ifdef _DEBUG
					_ASSERT(0);
#endif
					return -1;
				}
			}
			else
			{
				if (TLS_Handshake(&h[1], h_length) == false)
				{
					m_Mode = _ERROR;
					return -1;
				}
			}
		}
		else if (h->contenttype == 20) // change_cipher_spec(20)
		{
			unsigned char* changesiperspec = (unsigned char*)&h[1];
			if (changesiperspec[0] == 1) // SSL3_MT_CCS(1)
			{
				m_Mode = _SECURE_CONNECTED;
			}
		}
		else if (h->contenttype == 21) // alert(21)
		{
			if (m_Mode == _SECURE_CONNECTED)
			{
				unsigned char result[1024];
				m_ClientSecure.Decrypt((char*)&h[1], (char*)result, h_length, CRijndael::CBC);
				int alertlevel = result[0]; // warning(1), fatal(2)
				int alertdesc = result[1];	// close_notify(0), unexpected_message(10), bad_record_mac(20), decryption_failed_RESERVED(21), record_overflow(22), decompression_failure(30),
				// handshake_failure(40), no_certificate_RESERVED(41), bad_certificate(42), unsupported_certificate(43), certificate_revoked(44),
				// certificate_expired(45), certificate_unknown(46), illegal_parameter(47), unknown_ca(48), access_denied(49), decode_error(50),
				// decrypt_error(51), export_restriction_RESERVED(60), protocol_version(70),
			}
			else
			{
				unsigned char *result = (unsigned char*)&h[1];
				int alertlevel = result[0];
				int alertdesc = result[1];
			}
		}
		else if (h->contenttype == 23) // application_data(23)
		{
			if (m_Mode == _SECURE_CONNECTED)
			{
				unsigned char result[4096];
				unsigned char* ptr = h_length + 36 <= sizeof(result) ? result : new unsigned char[h_length];

				m_ClientSecure.Decrypt((char*)&h[1], (char*)ptr, h_length, CRijndael::CBC);
				int data_len = h_length - (ptr[h_length - 1] + 1 + 20);
				int iv_len = m_Version == 0x302 ? 16 : 0;
				if (data_len > iv_len && ReadData(&ptr[iv_len], data_len-iv_len) == false)
				{
					if (ptr != result)
						delete ptr;
					m_Mode = _ERROR;
					return -1;
				}
				if (ptr != result)
					delete ptr;
			}
		}
		else
		{
			m_Mode = _ERROR;
			return -1;
		}

		off += h_length + 5;
	}
	return off;
}

bool CTLS::ReadData(const void* ptr, int len)
{
	if (m_Offset == sizeof(m_Buffer))
		return false;

	if (m_Offset == 0)
	{
		int off = _OnRecv(ptr, len);
		if (off == -1)
			return false;
		if (len - off >= sizeof(m_Buffer))
			return false;
		if (len - off > 0)
		{
			memcpy(m_Buffer, (char*)ptr + off, len - off);
			m_Offset = len - off;
		}
	}
	else if (m_Offset + len > sizeof(m_Buffer))
	{
		int l = sizeof(m_Buffer) - m_Offset;
		if (ReadData(ptr, l) == false)
			return false;
		if (ReadData((char*)ptr + l, len - l) == false)
			return false;
	}
	else
	{
		memcpy(&m_Buffer[m_Offset], ptr, len);

		int off = _OnRecv(m_Buffer, m_Offset + len);
		if (off == -1)
			return false;
		int left = m_Offset + len - off;
		memmove(m_Buffer, &m_Buffer[off], left);
		m_Offset = left;
	}
	return true;
}

void CTLS::Send(const void* ptr, int len)
{
	if (m_Mode == _SECURE_CONNECTED)
	{
		SendTLSContents(23, ptr, len, true); // application_data(23)
	}
}

bool CTLS::TLS_ClientHello(char* ptr, int len)
{
	unsigned char* client_version = (unsigned char*)ptr;
	m_Version = client_version[1] == 1 ? 0x301 : 0x302;

	unsigned char random_gmt_unix_time[4];
	//unsigned char random_bytes_client[28];
	memcpy(random_gmt_unix_time, &ptr[2], 4);
	memcpy(m_ClientRandom, &ptr[2], 32);

	unsigned char sessionid[32];
	int sessionid_length = ptr[34];
	if (sessionid_length == 32)
		memcpy(sessionid, &ptr[35], sessionid_length);

	int offset = 35 + sessionid_length;

	static unsigned char TLS_RSA_WITH_AES_128_CBC_SHA[] = { 0x00, 0x2F };
	//static unsigned char TLS_RSA_WITH_AES_256_CBC_SHA[] = { 0x00, 0x35 };
	//static unsigned char TLS_RSA_WITH_AES_128_CBC_SHA256[] = { 0x00, 0x3C };
	//static unsigned char TLS_RSA_WITH_AES_256_CBC_SHA256[] = { 0x00, 0x3D };

	int algorithm = -1;

	int ciphersuite_length = convert_little_endian((unsigned char*)&ptr[offset], 2);
	for (int i = 0; i < ciphersuite_length; i += 2)
	{
		//unsigned char ciphersuite[2];
		//memcpy(ciphersuite, &ptr[offset + 2 + i], 2);
		if (!memcmp(&ptr[offset + 2 + i], TLS_RSA_WITH_AES_128_CBC_SHA, 2))
			algorithm = 0;
		//else if (!memcmp(&ptr[offset + 2 + i], TLS_RSA_WITH_AES_128_CBC_SHA256, 2))
		//	algorithm = 1;
	}
	if (algorithm == -1)
	{
		m_Mode = _ERROR;
		return false;
	}

	offset += 2 + ciphersuite_length;

	int compressionmethod_length = convert_little_endian((unsigned char*)&ptr[offset], 1);
	for (int i = 0; i < compressionmethod_length; i++)
	{
		unsigned char compressionmethod[1];
		memcpy(compressionmethod, &ptr[1 + offset + i], 1);
	}

	// Server Hello
	//unsigned char sessionid[32]; // 재연결시사용 (실제로 사용안함) <- 암호 연결 후 sessinoid, mastersecrect등 저장해두면 이후 연결시 인증서교환없이 사용할 수도 있다. (활용도는 높지 않아보임)

	m_ServerRandom[0] = random_gmt_unix_time[0]; // random_gmt_unix_time
	m_ServerRandom[1] = random_gmt_unix_time[1];
	m_ServerRandom[2] = random_gmt_unix_time[2];
	m_ServerRandom[3] = random_gmt_unix_time[3];
	for (int i = 4; i < 32; i++)
		m_ServerRandom[i] = rand() & 255;

	if (sessionid_length == 32)
	{
		unsigned char* mastersecret = FindMasterSecret(sessionid);

		if (mastersecret != NULL)
		{
			memcpy(m_SessionID, sessionid, 32);
			memcpy(m_MasterSecret, mastersecret, 48);

			UpdateMasterSecret(m_MasterSecret, m_ServerRandom, m_ClientRandom, true);

			SendTLSServerHello(m_ServerRandom, m_SessionID, 32, TLS_RSA_WITH_AES_128_CBC_SHA, 0);
			SendTLSChangeCipherSpec();
			m_ChangeCiperSpec = 1;
			SendTLSFinish("server finished");
			return true;
		}
	}

	static unsigned char _sessionid[32] = "S$K&*!mAAI2O@I(@#)(@!#*NFS@JHD("; // random

	do
	{
		for (int i = 0; i < 32; i++) {
			if (++_sessionid[32 - i - 1] != 0)
				break;
		}
	} while (sessionid_length == 32 && !memcmp(_sessionid, sessionid, 32));

	for (int i = 0; i < 32; i++)
		sessionid[i] = m_SessionID[i] = _sessionid[i];

	SendTLSServerHello(m_ServerRandom, sessionid, 32, TLS_RSA_WITH_AES_128_CBC_SHA, 0);

	// Certificate
	SendTLSCertificate((void**)s_Certificate, s_CertificateLength, s_Certificate[2] != NULL ? 3 : (s_Certificate[1] != NULL ? 2 : 1));

	// ServerHelloDone
	SendTLSHandshake(14, NULL, 0); // server_hello_done (14)
	return true;
}

void CTLS::SendTLSServerHello(const unsigned char* server_random_32, const unsigned char* sessionid, int sessionid_len, const unsigned char* ciphersuite, unsigned char compression_method)
{
	char packet[128];

	packet[0] = m_Version>>8; // version_high
	packet[1] = m_Version&255; // version_low
	memcpy(&packet[2], server_random_32, 32);

	packet[34] = sessionid_len; // sessionid_length;
	for (int i = 0; i<sessionid_len; i++)
		packet[35 + i] = sessionid[i];

	packet[35 + sessionid_len] = ciphersuite[0]; // TLS_RSA_WITH_AES_128_CBC_SHA{ 0x00, 0x2F };
	packet[36 + sessionid_len] = ciphersuite[1]; // TLS_RSA_WITH_AES_128_CBC_SHA{ 0x00, 0x2F };
	packet[37 + sessionid_len] = compression_method; // NO_COMPRESS
	SendTLSHandshake(2, packet, 38 + sessionid_len); // server_hello(2)
}

void CTLS::SendTLSCertificate(void* certificate, int certificate_length)
{
	SendTLSCertificate(&certificate, &certificate_length, 1);
}

void CTLS::SendTLSCertificate(void** certificate, int* certificate_length, int count)
{
	unsigned char packet[8192];
	int off = 0;
	for (int i = 0; i < count; i++)
	{
		int len = certificate_length[i];
		packet[3+off+0] = (len >> 16) & 255; // certificate_list_high(16-23)
		packet[3+off+1] = (len >> 8) & 255; // certificate_list_mid (8-15)
		packet[3+off+2] = len & 255; // certificate_list_low (0-7)
		memcpy(&packet[3+off+3], certificate[i], len);
		off += 3 + len;
	}

	packet[0] = (off >> 16) & 255; // certificate_list_high(16-23)
	packet[1] = (off >> 8) & 255; // certificate_list_mid (8-15)
	packet[2] = off & 255; // certificate_list_low (0-7)

	SendTLSHandshake(11, packet, 3 + off); // Certificate (11)
}

#include "md5.h"

void CTLS::P_MD5(const unsigned char* premaster_secret, int premaster_secret_len, const unsigned char* seed1, int seed1_len, const unsigned char* seed2, int seed2_len, unsigned char* out, int outlen)
{
	unsigned char msg[1024];

	memcpy(&msg[16], seed1, seed1_len);
	memcpy(&msg[16 + seed1_len], seed2, seed2_len);

	HMAC_MD5(premaster_secret, premaster_secret_len, &msg[16], seed1_len + seed2_len, &msg[0]);

	for (int i = 0; i < outlen; i += 16)
	{
		if (i != 0)
			HMAC_MD5(premaster_secret, premaster_secret_len, msg, 16, &msg[0]);

		if (i + 16 > outlen)
		{
			unsigned char temp[16];
			HMAC_MD5(premaster_secret, premaster_secret_len, msg, 16 + seed1_len + seed2_len, temp);
			memcpy(&out[i], temp, outlen - i);
		}
		else
		{
			HMAC_MD5(premaster_secret, premaster_secret_len, msg, 16 + seed1_len + seed2_len, &out[i]);
		}
	}
}

void CTLS::P_SHA1(const unsigned char* premaster_secret, int premaster_secret_len, const unsigned char* seed1, int seed1_len, const unsigned char* seed2, int seed2_len, unsigned char* out, int outlen)
{
	unsigned char msg[1024];

	memcpy(&msg[20], seed1, seed1_len);
	memcpy(&msg[20 + seed1_len], seed2, seed2_len);

	HMAC_Sha1(premaster_secret, premaster_secret_len, &msg[20], seed1_len + seed2_len, &msg[0]);

	for (int i = 0; i < outlen; i += 20)
	{
		if (i != 0)
			HMAC_Sha1(premaster_secret, premaster_secret_len, msg, 20, &msg[0]);

		if (i + 20 > outlen)
		{
			unsigned char temp[20];
			HMAC_Sha1(premaster_secret, premaster_secret_len, msg, 20 + seed1_len + seed2_len, temp);
			memcpy(&out[i], temp, outlen - i);
		}
		else
		{
			HMAC_Sha1(premaster_secret, premaster_secret_len, msg, 20 + seed1_len + seed2_len, &out[i]);
		}
	}
}

void CTLS::PRF(const unsigned char* premaster_secret, int premaster_secret_len, const char* label, const unsigned char* seed, int seed_length, unsigned char* output_master_secret, int output_master_secret_len)
{
	unsigned char p_md5[104];
	unsigned char p_sha1[104];

	int label_length = strlen(label);
	P_MD5(premaster_secret, premaster_secret_len / 2, (unsigned char*)label, label_length, seed, seed_length, p_md5, output_master_secret_len);
	P_SHA1(&premaster_secret[premaster_secret_len / 2], premaster_secret_len / 2, (unsigned char*)label, label_length, seed, seed_length, p_sha1, output_master_secret_len);

	for (int i = 0; i < output_master_secret_len; i++)
		output_master_secret[i] = p_md5[i] ^ p_sha1[i];
}

#include "pkcs1.h"

bool CTLS::TLS_ClientKeyExchange(char* ptr, int len)
{
	// Computing the master secret

	int rsa_size = convert_little_endian((unsigned char*)ptr, 2);

	unsigned char out[2048];
	unsigned int outlen = sizeof(out);
	pkcs1_v15_private_key_decrypt(m_PrivateKey, (unsigned char*)&ptr[2], rsa_size, out, &outlen);

	if (outlen != 48)
		return false;

	//unsigned char version_high = out[0];
	//unsigned char version_low = out[1];
	unsigned char* premaster_secret = &out[0]; // 46;

	UpdatePreMasterSecret(premaster_secret, m_ServerRandom, m_ClientRandom, true);

	InsertSessionID(m_SessionID, m_MasterSecret);
	return true;
}

void CTLS::UpdatePreMasterSecret(const unsigned char* premaster_secret, const unsigned char* serverrandom, const unsigned char* clientrandom, bool serverside)
{
	unsigned char seed[64];
	memcpy(seed, clientrandom, 32);
	memcpy(&seed[32], serverrandom, 32);

	PRF(premaster_secret, 48, "master secret", seed, 64, m_MasterSecret, 48);

	UpdateMasterSecret(m_MasterSecret, serverrandom, clientrandom, serverside);
}

void CTLS::UpdateMasterSecret(const unsigned char* master_secret, const unsigned char* serverrandom, const unsigned char* clientrandom, bool serverside)
{
	unsigned char seed[64];

	memcpy(seed, serverrandom, 32);
	memcpy(&seed[32], clientrandom, 32);

	//ase_128_cbc / keymaterial = 16, ivsize=16, blocksize=16, 
	//sha / mac_key_length = 20, mac_length = 20

	unsigned char key_expansion[104]; // 20+20+16+16+16+16
	PRF(master_secret, 48, "key expansion", seed, 64, key_expansion, 104);

	if (serverside == true)
	{
		memcpy(m_ClientMAC, &key_expansion[0], 20);
		memcpy(m_ServerMAC, &key_expansion[20], 20);

		m_ClientSecure.MakeKey((char*)&key_expansion[40], (char*)&key_expansion[72], 16, 16);
		m_ServerSecure.MakeKey((char*)&key_expansion[56], (char*)&key_expansion[88], 16, 16);
	}
	else
	{
		memcpy(m_ClientMAC, &key_expansion[20], 20);
		memcpy(m_ServerMAC, &key_expansion[0], 20);

		m_ClientSecure.MakeKey((char*)&key_expansion[56], (char*)&key_expansion[88], 16, 16);
		m_ServerSecure.MakeKey((char*)&key_expansion[40], (char*)&key_expansion[72], 16, 16);
	}
}

void CTLS::SendTLSContents(unsigned char contenttype, const void* data, int len, bool secure)
{
	if (secure == false)
	{
		char packet[512];
		packet[0] = contenttype; // handshake(22)
		packet[1] = m_Version>>8; // version_major
		packet[2] = m_Version&255; // version_minor
		packet[3] = (len >> 8) & 255; // length_high
		packet[4] = len & 255; // length_low
		if (5 + len <= sizeof(packet))
		{
			if (len > 0)
				memcpy(&packet[5], data, len);
			_SendRaw(packet, 5+len);
		}
		else
		{
			_SendRaw(packet, 5);
			_SendRaw(data, len);
		}
	}
	else
	{
		unsigned char temp[16 + 1024 + 20];
		unsigned char* head = &temp[16 - 13]; // 2:8
		unsigned char* packet = &head[13];
		unsigned char* mac = &packet[len];
		unsigned char* padding = &mac[20];
		int packetsize = (len + 20 + 1 + 15)&(~15);
#ifdef _DEBUG
		_ASSERT(len <= 1024);
#endif
		memcpy(head, m_ServerSeq, 8);
		head[8] = contenttype;
		head[9] = m_Version>>8; // version_major
		head[10] = m_Version&255; // version_minor
		head[11] = (len >> 8) & 255; // length_high
		head[12] = len & 255; // length_low

		memcpy(packet, data, len);
		HMAC_Sha1(m_ServerMAC, 20, head, 13 + len, mac); // 20 bytes

		unsigned char padding_length = packetsize - (len + 20) - 1;
		for (int i = len + 20; i < packetsize; i++)
			packet[i] = padding_length;

		char encoded[16 + 1024 + 20 + 16];
		int iv_len = m_Version == 0x302 ? 16 : 0;
		unsigned char* iv = &packet[-iv_len];
		for (int i = 0; i < iv_len; i++) //iv
			iv[i] = rand();
		m_ServerSecure.Encrypt((const char*)iv, encoded, iv_len + packetsize, CRijndael::CBC);
		SendTLSContents(contenttype, encoded, iv_len + packetsize, false);

		for (int i = 0; i < 8; i++)
		{
			if (++m_ServerSeq[7 - i] != 0)
				break;
		}
	}
}

void CTLS::SendTLSHandshake(unsigned char msg_type, const void* data, int len)
{
	char packet[512];
	packet[0] = 22; // handshake(22)
	packet[1] = m_Version>>8; // version_major
	packet[2] = m_Version&255; // version_minor
	packet[3] = ((4 + len) >> 8) & 255; // length_high
	packet[4] = (4 + len) & 255; // length_low

	// HANDSHAKE
	packet[5] = msg_type;
	packet[6] = (len >> 16) & 255; // handshake_high
	packet[7] = (len >> 8) & 255;
	packet[8] = len & 255; // handshake_low

	if (9 + len <= sizeof(packet))
	{
		if (len > 0)
			memcpy(&packet[9], data, len);
		_SendRaw(packet, 9 + len);

		UpdateHandshakeHash(&packet[5], 4 + len);
	}
	else
	{
		_SendRaw(packet, 9);
		_SendRaw(data, len);

		UpdateHandshakeHash(&packet[5], 4);
		UpdateHandshakeHash(data, len);
	}
}

void CTLS::UpdateHandshakeHash(const void* data, int len)
{
	int off = (m_HandshakeMessageLen & 63);

	if (off == 0 && len >= 64)
	{
		for (; off + 64 <= len; off += 64)
		{
			MD5_Update(m_HashshakeMD5, (char*)data + off);
			Sha1_Update(m_HashshakeSHA, (char*)data + off);
			m_HandshakeMessageLen += 64;
		}
		UpdateHandshakeHash((char*)data + off, len - off);
	}
	else if (off + len > 64)
	{
		UpdateHandshakeHash(data, 64 - off);
		UpdateHandshakeHash((char*)data + (64 - off), len - (64 - off));
	}
	else if (len > 0)
	{
		memcpy(m_HandshakeBlk + off, data, len);
		m_HandshakeMessageLen += len;

		if (off + len == 64)
		{
			MD5_Update(m_HashshakeMD5, m_HandshakeBlk);
			Sha1_Update(m_HashshakeSHA, m_HandshakeBlk);
		}
	}
}

void CTLS::GetHandshakeHash(unsigned char* hash36)
{
	memcpy(&hash36[0], m_HashshakeMD5, 16);
	memcpy(&hash36[16], m_HashshakeSHA, 20);

	MD5_Final(&hash36[0], m_HandshakeBlk, m_HandshakeMessageLen & 63, m_HandshakeMessageLen);
	Sha1_Final(&hash36[16], m_HandshakeBlk, m_HandshakeMessageLen & 63, m_HandshakeMessageLen);
}

bool CTLS::TLS_Handshake(const void * h_data, int h_length)
{
	if (m_ServerSide == false)
		return TLS_HandshakeClient(h_data, h_length);
	else
		return TLS_HandshakeServer(h_data, h_length);
}

bool CTLS::TLS_HandshakeServer(const void * h_data, int h_length)
{
	const HANDSHAKE* handshake = (HANDSHAKE*)h_data;

	int msg_type = handshake->msg_type;
	const unsigned char* data = (unsigned char*)&handshake[1];
	int data_length = convert_little_endian(handshake->length, 3);

	if (data_length + 4 > h_length)
		return false; // fail

	if (msg_type == 1) // client_hello(1)
	{
		UpdateHandshakeHash(h_data, data_length + 4);
		if (TLS_ClientHello((char*)data, data_length) == false)
			return false;
	}
	else if (msg_type == 16) // client_key_exchange(16)
	{
		UpdateHandshakeHash(h_data, data_length + 4);
		if (TLS_ClientKeyExchange((char*)data, data_length) == false)
			return false;
	}
	else if (msg_type == 20) // finished(20)
	{
		unsigned char temp_key[12];
		GetTLSKey("client finished", temp_key);

		if (memcmp(data, temp_key, 12))
			return false;

		unsigned char temp_hash[20];
		GetClientPacketHash(data, data_length, temp_hash);

		if (memcmp(temp_hash, &data[12], 20))
			return false;

		UpdateHandshakeHash(h_data, data_length + 4);

		if (m_ChangeCiperSpec == 0)
		{
			SendTLSChangeCipherSpec();
			m_ChangeCiperSpec = 1;
			SendTLSFinish("server finished");
		}
	}
	return true;
}

bool CTLS::TLS_HandshakeClient(const void * h_data, int h_length)
{
	const HANDSHAKE* handshake = (HANDSHAKE*)h_data;

	int msg_type = handshake->msg_type;
	const unsigned char* data = (unsigned char*)&handshake[1];
	int data_length = convert_little_endian(handshake->length, 3);

	if (data_length + 4 > h_length)
		return false; // fail

	if (msg_type == 2) // server_hello(2)
	{
		UpdateHandshakeHash(h_data, data_length + 4);

		unsigned char* version = (unsigned char*)&data[0];
		m_Version = version[1] == 1 ? 0x301 : 0x302;

		memcpy(m_ServerRandom, &data[2], 32);

		unsigned char sessionid_len = data[34];
		unsigned char sessionid[32];

		if (sessionid_len != 32)
			return false;

		for (int i = 0; i < sessionid_len; i++)
			sessionid[i] = data[35 + i];

		const unsigned char* cipersuite = &data[35 + sessionid_len];
		static unsigned char TLS_RSA_WITH_AES_128_CBC_SHA[] = { 0x00, 0x2F };
		unsigned char compressmethod = data[37 + sessionid_len];

		if (memcmp(cipersuite, TLS_RSA_WITH_AES_128_CBC_SHA, 2) || compressmethod != 0)
			return false;

		if (!memcmp(m_SessionID, sessionid, 32))
		{
			UpdateMasterSecret(m_MasterSecret, m_ServerRandom, m_ClientRandom, false);
		}
		else
		{
			memcpy(m_SessionID, sessionid, 32);
		}
	}
	else if (msg_type == 11) // certificate(11)
	{
		UpdateHandshakeHash(h_data, data_length + 4);

		int certificate_total_length = convert_little_endian(data, 3);

		static unsigned char rsa_sign[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
		const unsigned char* public_key;
		unsigned int public_key_length;

		for (int i = 0; i < certificate_total_length;)
		{
			int certificate_length = convert_little_endian(&data[3 + i], 3);

			if (ReadObjectValue(&data[3 + i + 3], certificate_length, rsa_sign, sizeof(rsa_sign), &public_key, &public_key_length))
			{
				//struct crypto_rsa_key* publickey;
				if (public_key[0] == 0)
					m_PublicKey = crypto_rsa_import_public_key(&public_key[1], public_key_length - 1);
				else
					m_PublicKey = crypto_rsa_import_public_key(public_key, public_key_length);
				break;
			}

			i += 3 + certificate_length;
		}

		if (m_PublicKey == NULL)
			return false;
	}
	else if (msg_type == 14) // server_hello_done(14)
	{
		UpdateHandshakeHash(h_data, data_length + 4);

		if (m_PublicKey == NULL)
			return false;

		unsigned char premaster_secret[48];
		premaster_secret[0] = m_Version>>8;
		premaster_secret[1] = m_Version&255;
		for (int i = 2; i < 48; i++)
			premaster_secret[i] = rand() & 255;

		UpdatePreMasterSecret(premaster_secret, m_ServerRandom, m_ClientRandom, false);

		// send client_key_exchange

		unsigned char sendpacket[256 + 2];
		unsigned char* premaster_encrypt = &sendpacket[2];
		unsigned int premaster_encrypt_len = 256;
		pkcs1_encrypt(2, m_PublicKey, 0, premaster_secret, 48, premaster_encrypt, &premaster_encrypt_len);

		sendpacket[0] = (premaster_encrypt_len >> 8) & 255;
		sendpacket[1] = (premaster_encrypt_len & 255);

		SendTLSHandshake(16, sendpacket, premaster_encrypt_len + 2); // client_key_exchange(16)

		crypto_rsa_free(m_PublicKey);
		m_PublicKey = NULL;

		// Server Change Cipher Spec

		SendTLSChangeCipherSpec();
		m_ChangeCiperSpec = 1;
		SendTLSFinish("client finished");
	}
	else if (msg_type == 20) // finished(20)
	{
		unsigned char temp_key[12];
		GetTLSKey("server finished", temp_key);

		if (memcmp(data, temp_key, 12))
			return false;

		unsigned char temp_hash[20];
		GetClientPacketHash(data, data_length, temp_hash);

		if (memcmp(temp_hash, &data[12], 20))
			return false;

		UpdateHandshakeHash(h_data, data_length + 4);

		if (m_ChangeCiperSpec == 0)
		{
			SendTLSChangeCipherSpec();
			m_ChangeCiperSpec = 1;
			SendTLSFinish("client finished");
		}
		return true;
	}

	if (data_length + 4 < h_length)
	{
		return TLS_HandshakeClient((char*)h_data + 4 + data_length, h_length - (4 + data_length));
	}

	return true;
}

void CTLS::SendTLSChangeCipherSpec()
{
	unsigned char change_cipher_spec[1] = { 1 };
	SendTLSContents(20, change_cipher_spec, 1, false); // change_cipher_spec(20)
}

void CTLS::SendTLSFinish(const char* label)
{
	char packet[4 + 12];
	packet[0] = 20; // finished(20)
	packet[1] = 0;
	packet[2] = 0;
	packet[3] = 12;
	GetTLSKey(label, (unsigned char*)&packet[4]);
	SendTLSContents(22, packet, 4 + 12, true); // handshake(22)

	UpdateHandshakeHash(packet, 12 + 4);
}

void CTLS::GetTLSKey(const char* label, unsigned char* key12)
{
	unsigned char hash[36];
	GetHandshakeHash(hash);

	PRF(m_MasterSecret, 48, label, hash, 16 + 20, key12, 12);
}

void CTLS::GetClientPacketHash(const void* msg, int msg_len, unsigned char* hash20)
{
	unsigned char temp[13 + 1024];
	memcpy(temp, m_ClientSeq, 8);
	temp[8] = 22; // handshake(22)
	temp[9] = m_Version>>8;
	temp[10] = m_Version&255;
	temp[11] = (msg_len + 4) >> 8;
	temp[12] = (msg_len + 4) & 255;
	temp[13 + 0] = 20;
	temp[13 + 1] = 0;
	temp[13 + 2] = msg_len >> 8;
	temp[13 + 3] = msg_len & 255;
	memcpy(&temp[13 + 4], msg, msg_len);
	HMAC_Sha1(m_ClientMAC, 20, temp, 13 + 4 + msg_len, hash20);
}

void CTLS::SetCertificate(const char* server_certificate_base64, const char* chain_certificate_base64, const char* root_certificate_base64)
{
	std::vector <unsigned char> sign[3];

	sign[0] = Base64Decode(server_certificate_base64);
	if (chain_certificate_base64)
		sign[1] = Base64Decode(chain_certificate_base64);
	if (root_certificate_base64)
		sign[2] = Base64Decode(root_certificate_base64);

	for (int i = 0; i < 3; i++)
	{
		if (sign[i].size() > 0)
		{
			int len = sign[i].size();
			s_Certificate[i] = new unsigned char[len];
			s_CertificateLength[i] = len;
			memcpy(s_Certificate[i], &sign[i][0], len);
		}
	}

	/*	static char _key[] = // CERTIFICATE
	"MIIDfjCCAmagAwIBAgIJAKRNsDKacUqNMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNV"
	"BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX"
	"aWRnaXRzIFB0eSBMdGQxEzARBgNVBAMTCnN1YmludGVyQ0EwHhcNMTUwNzAyMTMx"
	"OTQ5WhcNMzUwNzAyMTMxOTQ5WjBUMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29t"
	"ZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYD"
	"VQQDEwRsZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0Qo9WC/"
	"BKA70LtQJdwVGSXqr9dut3cQmiFzTb/SaWldjOT1sRNDFxSzdTJjU/8cIDEZvaTI"
	"wRxP/dtVQLjc+4jzrUwz93NuZYlsEWUEUg4Lrnfs0Nz50yHk4rJhVxWjb8Ii/wRB"
	"ViWHFExP7CwTkXiTclC1bCqTuWkjxF3thTfTsttRyY7qNkz2JpNx0guD8v4otQoY"
	"jA5AEZvK4IXLwOwxol5xBTMvIrvvff2kkh+c7OC2QVbUTow/oppjqIKCx2maNHCt"
	"LFTJELf3fwtRJLJsy4fKGP0/6kpZc8Sp88WK4B4FauF9IV1CmoAJUC1vJxhagHIK"
	"fVtFjUWs8GPobQIDAQABo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQcHcT+8SVG"
	"IRlN9YTuM9rlz7UZfzAfBgNVHSMEGDAWgBTpZ30QdMGarrhMPwk+HHAV3R8aTzAN"
	"BgkqhkiG9w0BAQsFAAOCAQEAGjmSkF8is+v0/RLcnSRiCXENz+yNi4pFCAt6dOtT"
	"6Gtpqa1tY5It9lVppfWb26JrygMIzOr/fB0r1Q7FtZ/7Ft3P6IXVdk3GDO0QsORD"
	"2dRAejhYpc5c7joHxAw9oRfKrEqE+ihVPUTcfcIuBaalvuhkpQRmKP71ws5DVzOw"
	"QhnMd0TtIrbKHaNQ4kNsmSY5fQolwB0LtNfTus7OEFdcZWhOXrWImKXN9jewPKdV"
	"mSG34NfXOnA6qx0eQg06z+TkdrptH6j1Va2vS1/bL+h1GxjpTHlvTGaZYxaloIjw"
	"y/EzY5jygRoABnR3eBm15CYZwwKL9izIq1H3OhymEi/Ycg==";*/

	/*
	30 82 03 7e                            ; SEQUENCE (37e 바이트)
	30 82 02 66                            ; SEQUENCE (266 바이트)
	|  a0 03                               ; OPTIONAL[0] (3 바이트)
	|  |  02 01                            ; INTEGER (1 바이트)
	|  |     02
	|  02 09                               ; INTEGER (9 바이트)
	|  |  00
	|  |  a4 4d b0 32 9a 71 4a 8d
	|  30 0d                               ; SEQUENCE (d 바이트)
	|  |  06 09                            ; OBJECT_ID (9 바이트)
	|  |  |  2a 86 48 86 f7 0d 01 01  0b
	|  |  |     ; 1.2.840.113549.1.1.11 sha256RSA
	|  |  05 00                            ; NULL (0 바이트)
	|  30 5a                               ; SEQUENCE (5a 바이트)
	|  |  31 0b                            ; SET (b 바이트)
	|  |  |  30 09                         ; SEQUENCE (9 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 06
	|  |  |     |     ; 2.5.4.6 국가/지역 (C)
	|  |  |     13 02                      ; PRINTABLE_STRING (2 바이트)
	|  |  |        41 55                                             ; AU
	|  |  |           ; "AU"
	|  |  31 13                            ; SET (13 바이트)
	|  |  |  30 11                         ; SEQUENCE (11 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 08
	|  |  |     |     ; 2.5.4.8 시/도 (S)
	|  |  |     13 0a                      ; PRINTABLE_STRING (a 바이트)
	|  |  |        53 6f 6d 65 2d 53 74 61  74 65                    ; Some-State
	|  |  |           ; "Some-State"
	|  |  31 21                            ; SET (21 바이트)
	|  |  |  30 1f                         ; SEQUENCE (1f 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 0a
	|  |  |     |     ; 2.5.4.10 조직 (O)
	|  |  |     13 18                      ; PRINTABLE_STRING (18 바이트)
	|  |  |        49 6e 74 65 72 6e 65 74  20 57 69 64 67 69 74 73  ; Internet Widgits
	|  |  |        20 50 74 79 20 4c 74 64                           ;  Pty Ltd
	|  |  |           ; "Internet Widgits Pty Ltd"
	|  |  31 13                            ; SET (13 바이트)
	|  |     30 11                         ; SEQUENCE (11 바이트)
	|  |        06 03                      ; OBJECT_ID (3 바이트)
	|  |        |  55 04 03
	|  |        |     ; 2.5.4.3 공통 이름 (CN)
	|  |        13 0a                      ; PRINTABLE_STRING (a 바이트)
	|  |           73 75 62 69 6e 74 65 72  43 41                    ; subinterCA
	|  |              ; "subinterCA"
	|  30 1e                               ; SEQUENCE (1e 바이트)
	|  |  17 0d                            ; UTC_TIME (d 바이트)
	|  |  |  31 35 30 37 30 32 31 33  31 39 34 39 5a           ; 150702131949Z
	|  |  |     ;  2015-07-02 오후 10:19
	|  |  17 0d                            ; UTC_TIME (d 바이트)
	|  |     33 35 30 37 30 32 31 33  31 39 34 39 5a           ; 350702131949Z
	|  |        ;  2035-07-02 오후 10:19
	|  30 54                               ; SEQUENCE (54 바이트)
	|  |  31 0b                            ; SET (b 바이트)
	|  |  |  30 09                         ; SEQUENCE (9 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 06
	|  |  |     |     ; 2.5.4.6 국가/지역 (C)
	|  |  |     13 02                      ; PRINTABLE_STRING (2 바이트)
	|  |  |        41 55                                             ; AU
	|  |  |           ; "AU"
	|  |  31 13                            ; SET (13 바이트)
	|  |  |  30 11                         ; SEQUENCE (11 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 08
	|  |  |     |     ; 2.5.4.8 시/도 (S)
	|  |  |     13 0a                      ; PRINTABLE_STRING (a 바이트)
	|  |  |        53 6f 6d 65 2d 53 74 61  74 65                    ; Some-State
	|  |  |           ; "Some-State"
	|  |  31 21                            ; SET (21 바이트)
	|  |  |  30 1f                         ; SEQUENCE (1f 바이트)
	|  |  |     06 03                      ; OBJECT_ID (3 바이트)
	|  |  |     |  55 04 0a
	|  |  |     |     ; 2.5.4.10 조직 (O)
	|  |  |     13 18                      ; PRINTABLE_STRING (18 바이트)
	|  |  |        49 6e 74 65 72 6e 65 74  20 57 69 64 67 69 74 73  ; Internet Widgits
	|  |  |        20 50 74 79 20 4c 74 64                           ;  Pty Ltd
	|  |  |           ; "Internet Widgits Pty Ltd"
	|  |  31 0d                            ; SET (d 바이트)
	|  |     30 0b                         ; SEQUENCE (b 바이트)
	|  |        06 03                      ; OBJECT_ID (3 바이트)
	|  |        |  55 04 03
	|  |        |     ; 2.5.4.3 공통 이름 (CN)
	|  |        13 04                      ; PRINTABLE_STRING (4 바이트)
	|  |           6c 65 61 66                                       ; leaf
	|  |              ; "leaf"
	|  30 82 01 22                         ; SEQUENCE (122 바이트)
	|  |  30 0d                            ; SEQUENCE (d 바이트)
	|  |  |  06 09                         ; OBJECT_ID (9 바이트)
	|  |  |  |  2a 86 48 86 f7 0d 01 01  01
	|  |  |  |     ; 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
	|  |  |  05 00                         ; NULL (0 바이트)
	|  |  03 82 01 0f                      ; BIT_STRING (10f 바이트)
	|  |     00
	|  |     30 82 01 0a                   ; SEQUENCE (10a 바이트)
	|  |        02 82 01 01                ; INTEGER (101 바이트)
	|  |        |  00
	|  |        |  bf 44 28 f5 60 bf 04 a0  3b d0 bb 50 25 dc 15 19
	|  |        |  25 ea af d7 6e b7 77 10  9a 21 73 4d bf d2 69 69
	|  |        |  5d 8c e4 f5 b1 13 43 17  14 b3 75 32 63 53 ff 1c
	|  |        |  20 31 19 bd a4 c8 c1 1c  4f fd db 55 40 b8 dc fb
	|  |        |  88 f3 ad 4c 33 f7 73 6e  65 89 6c 11 65 04 52 0e
	|  |        |  0b ae 77 ec d0 dc f9 d3  21 e4 e2 b2 61 57 15 a3
	|  |        |  6f c2 22 ff 04 41 56 25  87 14 4c 4f ec 2c 13 91
	|  |        |  78 93 72 50 b5 6c 2a 93  b9 69 23 c4 5d ed 85 37
	|  |        |  d3 b2 db 51 c9 8e ea 36  4c f6 26 93 71 d2 0b 83
	|  |        |  f2 fe 28 b5 0a 18 8c 0e  40 11 9b ca e0 85 cb c0
	|  |        |  ec 31 a2 5e 71 05 33 2f  22 bb ef 7d fd a4 92 1f
	|  |        |  9c ec e0 b6 41 56 d4 4e  8c 3f a2 9a 63 a8 82 82
	|  |        |  c7 69 9a 34 70 ad 2c 54  c9 10 b7 f7 7f 0b 51 24
	|  |        |  b2 6c cb 87 ca 18 fd 3f  ea 4a 59 73 c4 a9 f3 c5
	|  |        |  8a e0 1e 05 6a e1 7d 21  5d 42 9a 80 09 50 2d 6f
	|  |        |  27 18 5a 80 72 0a 7d 5b  45 8d 45 ac f0 63 e8 6d
	|  |        02 03                      ; INTEGER (3 바이트)
	|  |           01 00 01
	|  a3 4d                               ; OPTIONAL[3] (4d 바이트)
	|     30 4b                            ; SEQUENCE (4b 바이트)
	|        30 09                         ; SEQUENCE (9 바이트)
	|        |  06 03                      ; OBJECT_ID (3 바이트)
	|        |  |  55 1d 13
	|        |  |     ; 2.5.29.19 기본 제한
	|        |  04 02                      ; OCTET_STRING (2 바이트)
	|        |     30 00                   ; SEQUENCE (0 바이트)
	|        30 1d                         ; SEQUENCE (1d 바이트)
	|        |  06 03                      ; OBJECT_ID (3 바이트)
	|        |  |  55 1d 0e
	|        |  |     ; 2.5.29.14 주체 키 식별자
	|        |  04 16                      ; OCTET_STRING (16 바이트)
	|        |     04 14                   ; OCTET_STRING (14 바이트)
	|        |        1c 1d c4 fe f1 25 46 21  19 4d f5 84 ee 33 da e5  ; .....%F!.M...3..
	|        |        cf b5 19 7f                                       ; ....
	|        30 1f                         ; SEQUENCE (1f 바이트)
	|           06 03                      ; OBJECT_ID (3 바이트)
	|           |  55 1d 23
	|           |     ; 2.5.29.35 기관 키 식별자
	|           04 18                      ; OCTET_STRING (18 바이트)
	|              30 16                   ; SEQUENCE (16 바이트)
	|                 80 14                ; CONTEXT_SPECIFIC[0] (14 바이트)
	|                    e9 67 7d 10 74 c1 9a ae  b8 4c 3f 09 3e 1c 70 15  ; .g}.t....L?.>.p.
	|                    dd 1f 1a 4f                                       ; ...O
	30 0d                                  ; SEQUENCE (d 바이트)
	|  06 09                               ; OBJECT_ID (9 바이트)
	|  |  2a 86 48 86 f7 0d 01 01  0b
	|  |     ; 1.2.840.113549.1.1.11 sha256RSA
	|  05 00                               ; NULL (0 바이트)
	03 82 01 01                            ; BIT_STRING (101 바이트)
	00
	1a 39 92 90 5f 22 b3 eb  f4 fd 12 dc 9d 24 62 09
	71 0d cf ec 8d 8b 8a 45  08 0b 7a 74 eb 53 e8 6b
	69 a9 ad 6d 63 92 2d f6  55 69 a5 f5 9b db a2 6b
	ca 03 08 cc ea ff 7c 1d  2b d5 0e c5 b5 9f fb 16
	dd cf e8 85 d5 76 4d c6  0c ed 10 b0 e4 43 d9 d4
	40 7a 38 58 a5 ce 5c ee  3a 07 c4 0c 3d a1 17 ca
	ac 4a 84 fa 28 55 3d 44  dc 7d c2 2e 05 a6 a5 be
	e8 64 a5 04 66 28 fe f5  c2 ce 43 57 33 b0 42 19
	cc 77 44 ed 22 b6 ca 1d  a3 50 e2 43 6c 99 26 39
	7d 0a 25 c0 1d 0b b4 d7  d3 ba ce ce 10 57 5c 65
	68 4e 5e b5 88 98 a5 cd  f6 37 b0 3c a7 55 99 21
	b7 e0 d7 d7 3a 70 3a ab  1d 1e 42 0d 3a cf e4 e4
	76 ba 6d 1f a8 f5 55 ad  af 4b 5f db 2f e8 75 1b
	18 e9 4c 79 6f 4c 66 99  63 16 a5 a0 88 f0 cb f1
	33 63 98 f2 81 1a 00 06  74 77 78 19 b5 e4 26 19
	c3 02 8b f6 2c c8 ab 51  f7 3a 1c a6 12 2f d8 72
	*/
}

#include "rsa_sign.h"

void CTLS::SetPrivateKey(const char* text_base64)
{
	std::vector <unsigned char> key = Base64Decode(text_base64);

	const unsigned char* rsa_sequence;
	unsigned int rsa_sequence_length;
	static unsigned char _RSA_SIGN[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

	if (ReadObjectValue(&key[0], key.size(), _RSA_SIGN, sizeof(_RSA_SIGN), &rsa_sequence, &rsa_sequence_length))
		m_PrivateKey = crypto_rsa_import_private_key(rsa_sequence, rsa_sequence_length);
	else
		m_PrivateKey = crypto_rsa_import_private_key(&key[0], key.size());

	/*	static char _privatekey[] =
	"MIIEpAIBAAKCAQEAv0Qo9WC/BKA70LtQJdwVGSXqr9dut3cQmiFzTb/SaWldjOT1"
	"sRNDFxSzdTJjU/8cIDEZvaTIwRxP/dtVQLjc+4jzrUwz93NuZYlsEWUEUg4Lrnfs"
	"0Nz50yHk4rJhVxWjb8Ii/wRBViWHFExP7CwTkXiTclC1bCqTuWkjxF3thTfTsttR"
	"yY7qNkz2JpNx0guD8v4otQoYjA5AEZvK4IXLwOwxol5xBTMvIrvvff2kkh+c7OC2"
	"QVbUTow/oppjqIKCx2maNHCtLFTJELf3fwtRJLJsy4fKGP0/6kpZc8Sp88WK4B4F"
	"auF9IV1CmoAJUC1vJxhagHIKfVtFjUWs8GPobQIDAQABAoIBAB1fCiskQDElqgnT"
	"uesWcOb7u55lJstlrVb97Ab0fgtR8tvADTq0Colw1F4a7sXnVxpab+l/dJSzFFWX"
	"aPAXc1ftH/5sxU4qm7lb8Qx6xr8TCRgxslwgkvypJ8zoN6p32DFBTr56mM3x1Vx4"
	"m41Y92hPa9USL8n8f9LpImT1R5Q9ShI/RUCowPyzhC6OGkFSBJu72nyA3WK0znXn"
	"q5TNsTRdJLOug7eoJJvhOPfy3neNQV0f2jQ+2wDKCYvn6i4j9FSLgYC/vorqofEd"
	"vFBHxl374117F6DXdBChyD4CD5vsplB0zcExRUCT5+iBqf5uc8CbLHeyNk6vSaf5"
	"BljHWsECgYEA93QnlKsVycgCQqHt2q8EIZ5p7ksGYRVfBEzgetsNdpxvSwrLyLQE"
	"L5AKG3upndOofCeJnLuQF1j954FjCs5Y+8Sy2H1D1EPrHSBp4ig2F5aOxT3vYROd"
	"v+/mF4ZUzlIlv3jNDz5IoLaxm9vhXTtLLUtQyTueGDmqwlht0Kr3/gcCgYEAxd86"
	"Q23jT4DmJqUl+g0lWdc2dgej0jwFfJ2BEw/Q55vHjqj96oAX5QQZFOUhZU8Otd/D"
	"lLzlsFn0pOaSW/RB4l5Kv8ab+ZpxfAV6Gq47nlfzmEGGx4wcoL0xkHufiXg0sqaG"
	"UtEMSKFhxPQZhWojUimK/+YIF69molxA6G9miOsCgYEA8mICSytxwh55qE74rtXz"
	"1AJZfKJcc0f9tDahQ3XBsEb29Kh0h/lciEIsxFLTB9dFF6easb0/HL98pQElxHXu"
	"z14SWOAKSqbka7lOPcppgZ1l52oNSiduw4z28mAQPbBVbUGkiqPVfCa3vhUYoLvt"
	"nUZCsXoGF3CVBJydpGFzXI0CgYEAtt3Jg72PoM8YZEimI0R462F4xHXlEYtE6tjJ"
	"C+vG/fU65P4Kw+ijrJQv9d6YEX+RscXdg51bjLJl5OvuAStopCLOZBPR3Ei+bobF"
	"RNkW4gyYZHLSc6JqZqbSopuNYkeENEKvyuPFvW3f5FxPJbxkbi9UdZCKlBEXAh/O"
	"IMGregcCgYBC8bS7zk6KNDy8q2uC/m/g6LRMxpb8G4jsrcLoyuJs3zDckBjQuLJQ"
	"IOMXcQBWN1h+DKekF2ecr3fJAJyEv4pU4Ct2r/ZTYFMdJTyAbjw0mqOjUR4nsdOh"
	"t/vCbt0QW3HXYTcVdCnFqBtelKnI12KoC0jAO9EAJGZ6kE/NwG6dQg==";*/
}

void* CTLS::s_Certificate[3] = { NULL, NULL, NULL };
int CTLS::s_CertificateLength[3] = { 0, 0, 0 };

struct crypto_rsa_key* CTLS::m_PrivateKey;

#include <time.h>

void CTLS::SendClientHello(const unsigned char* sessionid32, const unsigned char* mastersecret48, int ver)
{
	m_ServerSide = false;
	if (ver != 0)
		m_Version = ver;

	unsigned char packet[128];
	packet[0] = m_Version>>8; // version_high
	packet[1] = m_Version&255; // version_low (1.1 로 요청 0x302)
	unsigned long random_gmt_unix_time = (unsigned long)time(NULL);
	packet[5] = (random_gmt_unix_time >> 24) & 255;
	packet[4] = (random_gmt_unix_time >> 16) & 255;
	packet[3] = (random_gmt_unix_time >> 8) & 255;
	packet[2] = random_gmt_unix_time & 255;

	for (int i = 4; i < 32; i++) // client random
		packet[2 + i] = rand() & 255;

	memcpy(m_ClientRandom, &packet[2], 32);

	int sessionid_length = sessionid32 != NULL ? 32 : 0;
	packet[34] = sessionid_length; // session id length
	for (int i = 0; i < sessionid_length; i++)
		packet[35 + i] = m_SessionID[i] = sessionid32[i];

	if (mastersecret48 != NULL)
		memcpy(m_MasterSecret, mastersecret48, 48);

	packet[35 + sessionid_length] = 0;
	packet[36 + sessionid_length] = 2;

	static unsigned char TLS_RSA_WITH_AES_128_CBC_SHA[] = { 0x00, 0x2F };

	packet[37 + sessionid_length] = TLS_RSA_WITH_AES_128_CBC_SHA[0];
	packet[38 + sessionid_length] = TLS_RSA_WITH_AES_128_CBC_SHA[1];

	packet[39 + sessionid_length] = 1;
	packet[40 + sessionid_length] = 0; // no comp

	SendTLSHandshake(1, packet, 41 + sessionid_length); // client_hello
}

CTLS::_SESSION CTLS::s_SessionList[];
int CTLS::s_SessionCount = 0;

void CTLS::InsertSessionID(const unsigned char* sessionid, const unsigned char* mastersecret)
{
	int idx = s_SessionCount % (sizeof(s_SessionList) / sizeof(*s_SessionList));
	memcpy(s_SessionList[idx].sessionid, sessionid, 32);
	memcpy(s_SessionList[idx].mastersecret, mastersecret, 48);
	s_SessionCount++;
}

unsigned char* CTLS::FindMasterSecret(const unsigned char* sessionid)
{
	for (int i = 0; i < s_SessionCount && i < (sizeof(s_SessionList) / sizeof(*s_SessionList)); i++)
	{
		if (!memcmp(s_SessionList[i].sessionid, sessionid, 32))
			return s_SessionList[i].mastersecret;
	}
	return NULL;
}