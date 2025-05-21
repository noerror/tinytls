#ifndef _TLS_H
#define _TLS_H

#include "rijndael.h"

class CTLS
{
public:
	CTLS();

	void Reset();
	void SendClientHello(const unsigned char* sessionid32=NULL, const unsigned char* mastersecret48=NULL, int ver=0); // client mode

	int OnRecv(const void* buff, int len);
	void Send(const void* ptr, int len);

	static void SetCertificate(const char* cerver_certificate_base64, const char* chain_certificate_base64 = NULL, const char* root_certificate_base64=NULL);
	static void SetPrivateKey(const char* text_base64);

	bool IsHandshakeCompleted() { return m_Mode == _SECURE_CONNECTED ? true : false; }

	const unsigned char* GetSession() { return m_SessionID; }
	const unsigned char* GetMasterSecret() { return m_MasterSecret; }

protected :
	virtual int _OnRecv(const void* ptr, int len) { return len; }
	virtual void _SendRaw(const void* ptr, int len) {}
	virtual bool ReadData(const void* ptr, int len);

protected :
	enum
	{
		_HANDSHAKE,
		_SECURE_CONNECTED,
		_ERROR,
	}	m_Mode;

	void SendTLSHandshake(unsigned char msg_type, const void* data, int len);
	void SendTLSContents(unsigned char contenttype, const void* data, int len, bool secure);

	void SendTLSCertificate(void* certificate, int certificate_length);
	void SendTLSCertificate(void** certificate, int* certificate_length, int count);
	void SendTLSServerHello(const unsigned char* server_random_32, const unsigned char* sessionid, int sessionid_len, const unsigned char* ciphersuite, unsigned char compression_method);
	void SendTLSFinish(const char* label);
	void SendTLSChangeCipherSpec();

       void UpdatePreMasterSecret(const unsigned char* premaster_secret, const unsigned char* serverrandom, const unsigned char* clientrandom, bool serverside);
       void UpdateMasterSecret(const unsigned char* master_secret, const unsigned char* serverrandom, const unsigned char* clientrandom, bool serverside);
	void GetTLSKey(const char* label, unsigned char* key12);
	void GetClientPacketHash(const void* msg, int msg_len, unsigned char* hash20);

	bool TLS_ClientHello(char* ptr, int len);
	bool TLS_ClientKeyExchange(char* ptr, int len);
	bool TLS_Handshake(const void * data, int length);
	bool TLS_HandshakeClient(const void * data, int length);
	bool TLS_HandshakeServer(const void * data, int length);

	static void P_MD5(const unsigned char* premaster_secret, int premaster_secret_len, const unsigned char* seed1, int seed1_len, const unsigned char* seed2, int seed2_len, unsigned char* out, int outlen);
	static void P_SHA1(const unsigned char* premaster_secret, int premaster_secret_len, const unsigned char* seed1, int seed1_len, const unsigned char* seed2, int seed2_len, unsigned char* out, int outlen);
	static void PRF(const unsigned char* master_secret, int master_secret_len, const char* label, const unsigned char* seed, int seed_length, unsigned char* output_master_secret, int output_master_secret_len);

	unsigned char m_ClientRandom[32];
	unsigned char m_ServerRandom[32];

	unsigned char m_SessionID[32];

	unsigned char m_MasterSecret[48];

	unsigned char m_ClientMAC[20];
	unsigned char m_ServerMAC[20];
	unsigned char m_ServerSeq[8];
	unsigned char m_ClientSeq[8];

	int m_ChangeCiperSpec;
	bool m_ServerSide;
	int m_Version;

	void UpdateHandshakeHash(const void* data, int len);
	void GetHandshakeHash(unsigned char* hash36);

	unsigned char m_HandshakeBlk[64], m_HashshakeMD5[16], m_HashshakeSHA[20];
	int m_HandshakeMessageLen;

	struct crypto_rsa_key* m_PublicKey;

	CRijndael m_ClientSecure;
	CRijndael m_ServerSecure;

private:
	unsigned char m_Buffer[1024];
	int m_Offset;

private :
	static void* s_Certificate[3];
	static int s_CertificateLength[3];

	static struct crypto_rsa_key* m_PrivateKey;

	static struct _SESSION
	{
		unsigned char sessionid[32];
		unsigned char mastersecret[48];
	}	s_SessionList[256];
	static int s_SessionCount;

	static void InsertSessionID(const unsigned char* sessionid, const unsigned char* mastersecret);
	static unsigned char* FindMasterSecret(const unsigned char* sessionid);
};

#endif