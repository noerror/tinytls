#ifndef __RIJNDAEL_H__
#define __RIJNDAEL_H__

#include <exception>
#include <cstring>

using namespace std;

//Rijndael (pronounced Reindaal) is a block cipher, designed by Joan Daemen and Vincent Rijmen as a candidate algorithm for the AES.
//The cipher has a variable block length and key length. The authors currently specify how to use keys with a length
//of 128, 192, or 256 bits to encrypt blocks with al length of 128, 192 or 256 bits (all nine combinations of
//key length and block length are possible). Both block length and key length can be extended very easily to
// multiples of 32 bits.
//Rijndael can be implemented very efficiently on a wide range of processors and in hardware. 
//This implementation is based on the Java Implementation used with the Cryptix toolkit found at:
//http://www.esat.kuleuven.ac.be/~rijmen/rijndael/rijndael.zip
//Java code authors: Raif S. Naffah, Paulo S. L. M. Barreto
//This Implementation was tested against KAT test published by the authors of the method and the
//results were identical.
class CRijndael
{
public:
	CRijndael();

	enum { DEFAULT_BLOCK_SIZE = 16 };
	enum { MAX_BLOCK_SIZE = 32, MAX_ROUNDS = 14, MAX_KC = 8, MAX_BC = 8 };

	bool MakeKey(char const* key, char const* chain=NULL, int keylength=DEFAULT_BLOCK_SIZE, int blockSize=DEFAULT_BLOCK_SIZE);

	enum { ECB = 0, CBC = 1, CFB = 2 }; //The Electronic Code Book (ECB), Cipher Block Chaining (CBC) and Cipher Feedback Block (CFB) modes

	bool Encrypt(char const* in, char* result, int n, int iMode = ECB);
	bool Decrypt(char const* in, char* result, int n, int iMode = ECB);

private:
	void Xor(char* buff, char const* chain);
	void DefEncryptBlock(char const* in, char* result);
	void DefDecryptBlock(char const* in, char* result);
	void EncryptBlock(char const* in, char* result);
	void DecryptBlock(char const* in, char* result);

	static int Mul(int a, int b);
	static int Mul4(int a, char b[]);
	
private:
	static const int sm_alog[256];
	static const int sm_log[256];
	static const char sm_S[256];
    static const char sm_Si[256];
    static const int sm_T1[256];
    static const int sm_T2[256];
    static const int sm_T3[256];
    static const int sm_T4[256];
    static const int sm_T5[256];
    static const int sm_T6[256];
    static const int sm_T7[256];
    static const int sm_T8[256];
    static const int sm_U1[256];
    static const int sm_U2[256];
    static const int sm_U3[256];
    static const int sm_U4[256];
    static const char sm_rcon[30];
    static const int sm_shifts[3][4][2];
	//Error Messages
	static char const* sm_szErrorMsg1;
	static char const* sm_szErrorMsg2;

private :
	bool m_bKeyInit; //Key Initialization Flag

	int m_Ke[MAX_ROUNDS+1][MAX_BC]; //Encryption (m_Ke) round key
    int m_Kd[MAX_ROUNDS+1][MAX_BC]; //Decryption (m_Kd) round key
	int m_keylength; //Key Length
	int	m_blockSize; //Block Size
	int m_iROUNDS; //Number of Rounds
	char m_chain0[MAX_BLOCK_SIZE]; //Chain Block
	char m_chain[MAX_BLOCK_SIZE];
	int tk[MAX_KC]; //Auxiliary private use buffers
	int a[MAX_BC];
	int t[MAX_BC];
};

#endif // __RIJNDAEL_H__

