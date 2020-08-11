#include <string.h>
#include "md5.h"

static int rol(int num, int cnt)
{
	return (int)(((unsigned)num << cnt) | ((unsigned)num >> (32 - cnt)));
}

// [MD5] https://gist.github.com/creationix/4710780
// leftrotate function definition
//#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
// These vars will contain the hash
//uint32_t h0, h1, h2, h3;

// Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating
// r specifies the per-round shift amounts
static unsigned int _r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

// Use binary integer part of the sines of integers (in radians) as constants// Initialize variables:
static unsigned int _k[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

static void MD5_Hash(const unsigned int* blk16, unsigned int* h)
{
	unsigned int a = h[0];
	unsigned int b = h[1];
	unsigned int c = h[2];
	unsigned int d = h[3];
	int i;

	for (i = 0; i<64; i++)
	{
		unsigned int f, g;

		if (i < 16) {
			f = (b & c) | ((~b) & d);
			g = i;
		}
		else if (i < 32) {
			f = (d & b) | ((~d) & c);
			g = (5 * i + 1);
		}
		else if (i < 48) {
			f = b ^ c ^ d;
			g = (3 * i + 5);
		}
		else {
			f = c ^ (b | (~d));
			g = (7 * i);
		}

		unsigned int temp = d;
		unsigned int code = blk16[g & 15];
		d = c;
		c = b;
		b = b + rol((a + f + _k[i] + code), _r[i]);
		a = temp;
	}

	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
}

static void MD5_Hash_Tail(const unsigned int* blk16, int len, int lenpos, unsigned int bits_len, unsigned int* h)
{
	unsigned char temp[64];
	memset(temp, 0, 64);
	if (len > 0)
		memcpy(temp, blk16, len);
	if (len >= 0 && len < 64)
		temp[len] = 128;
	if (lenpos >= 0 && lenpos < 64) // lenpos == (448/8) = (56)
		memcpy(&temp[lenpos], &bits_len, 4);
	MD5_Hash((unsigned int*)temp, h);
}

void MD5_Init(unsigned char* output_hash_16)
{
	static unsigned int h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	memcpy(output_hash_16, h, 16);
}

void MD5_Update(unsigned char* output_hash_16, const void *msg64)
{
	MD5_Hash(msg64, (unsigned int*)output_hash_16);
}

void MD5_Final(unsigned char* output_hash_16, const void* msg, int msg_len, int total_length)
{
	int bitcount = msg_len * 8 + 1;
	int new_len = (bitcount + ((bitcount & 511) <= 448 ? 448 : 512 + 448) - (bitcount & 511)) / 8;
	int offset;

	for (offset = 0; offset + 64 <= msg_len && offset<new_len; offset += 64)
		MD5_Hash((unsigned int *)((char*)msg + offset), (unsigned int*)output_hash_16);

	for (; offset<new_len; offset += 64)
		MD5_Hash_Tail((unsigned int *)((char*)msg + offset), msg_len - offset, new_len - offset, 8 * total_length, (unsigned int*)output_hash_16);
}

void MD5(const unsigned char *msg, int msg_len, unsigned char* hash16)
{
	unsigned char h[16];
	MD5_Init(h);
	MD5_Final(h, msg, msg_len, msg_len);
	memcpy(hash16, h, 16);
}

// https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Design_principles

static void MD5Mix(const unsigned char *msg1, int msg1_len, const unsigned char *msg2, int msg2_len, unsigned char* hash16)
{
	unsigned int h[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

	int length = msg1_len + msg2_len;
	int bitcount = length * 8 + 1;
	int new_len = (bitcount + ((bitcount & 511) <= 448 ? 448 : 512 + 448) - (bitcount & 511)) / 8;
	int off;

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	for (off = 0; off<new_len; off += 64)
	{
		if (off + 64 <= msg1_len)
		{
			MD5_Hash((unsigned int *)(msg1 + off), h);
		}
		else if (off + 64 <= length)
		{
			if (off < msg1_len)
			{
				unsigned char temp[64];
				int l = msg1_len - off;
				memcpy(temp, msg1 + off, l);
				memcpy(&temp[l], msg2, 64-l);
				MD5_Hash((unsigned int *)temp, h);
			}
			else
			{
				MD5_Hash((unsigned int *)(msg2 + (off - msg1_len)), h);
			}
		}
		else
		{
			unsigned char temp[64];
			if (off < msg1_len)
			{
				memcpy(temp, msg1 + off, msg1_len - off);
			}
			if (off < length)
			{
				if (off < msg1_len)
					memcpy(temp + (msg1_len - off), msg2, msg2_len);
				else
					memcpy(temp, &msg2[off - msg1_len], length - off);
			}
			if (length > off)
				memset(temp + length - off, 0, 64 - (length - off));
			else
				memset(temp, 0, 64);
			MD5_Hash_Tail((unsigned int *)temp, length - off, new_len - off, 8 * length, h);
		}
	}

	memcpy(hash16, h, 16);
}

void HMAC_MD5(const unsigned char* key, int key_len, const unsigned char* message, int msg_len, unsigned char* output_hash_16)
{
	if (key_len > 64)
	{
		unsigned char key_hash[16];
		MD5(key, key_len, key_hash);
		HMAC_MD5(key_hash, 16, message, msg_len, output_hash_16);
	}
	else if (key_len < 64)
	{
		unsigned char temp[64];
		if (key_len > 0)
			memcpy(temp, key, key_len);
		memset(&temp[key_len], 0, 64 - key_len);
		HMAC_MD5(temp, 64, message, msg_len, output_hash_16);
	}
	else
	{
		unsigned char o_key_pad[64];
		unsigned char i_key_pad[64];
		int i;

		for (i = 0; i < 64; i++)
		{
			o_key_pad[i] = 0x5c ^ key[i];
			i_key_pad[i] = 0x36 ^ key[i];
		}

		unsigned char i_hash[16];

		MD5Mix(i_key_pad, 64, message, msg_len, i_hash);
		MD5Mix(o_key_pad, 64, i_hash, 16, output_hash_16);
	}
}