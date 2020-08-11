#include <string.h>
#include "sha1.h"

// http://intertwingly.net/stories/2004/07/18/SHA1.java

static int rol(int num, int cnt)
{
	return (int)(((unsigned)num << cnt) | ((unsigned)num >> (32 - cnt)));
}

static void Transform(const unsigned char* data, int len, int blklen, int total, int* h)
{
	int a = h[0];
	int b = h[1];
	int c = h[2];
	int d = h[3];
	int e = h[4];

	// calculate 160 bit SHA1 hash of the sequence of blocks
	int w[80];
	int j;
	for (j = 0; j < 80; j++)
	{
		if (j < 16)
		{
			int code = 0;
			int off = j * 4;
			int k;

			for (k = 0; k < 4 && off + k < len; k++)
				code |= data[off + k] << (24 - (k & 3) * 8);

			if (off <= len && off + 4 > len)
				code |= 0x80 << (24 - (len - off) * 8);

			if (j == blklen - 1)
				code = total * 8;
			w[j] = code;
		}
		else
		{
			w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
		}

		int t = rol(a, 5) + e + w[j] +
			((j < 20) ? 1518500249 + ((b & c) | ((~b) & d))
			: (j < 40) ? 1859775393 + (b ^ c ^ d)
			: (j < 60) ? -1894007588 + ((b & c) | (b & d) | (c & d))
			: -899497514 + (b ^ c ^ d));
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = t;
	}

	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void Sha1(const unsigned char* data, int len, unsigned char* output20)
{
	// Convert a string to a sequence of 16-word blocks, stored as an array.
	// Append padding bits and the length, as described in the SHA1 standard
	int blklen = (((len + 8) >> 6) + 1) * 16;

	int h[5] = { 1732584193, -271733879, -1732584194, 271733878, -1009589776 };
	int i, off;

	for (i = 0, off = 0; i < blklen; i += 16, off += 16 * 4)
		Transform(&data[off], len - off, blklen - i, len, h);

	for (i = 0; i < 20; i++)
		output20[i] = h[i / 4] >> (8 * (3 - (i & 3)));
}

void Sha1_Init(unsigned char* output_hash_20)
{
	static int h[5] = { 1732584193, -271733879, -1732584194, 271733878, -1009589776 };
	memcpy(output_hash_20, h, 20);
}

void Sha1_Update(unsigned char* output_hash_20, const void *msg64)
{
	Transform((unsigned char*)msg64, 64, 64, 0, (int*)output_hash_20);
}

void Sha1_Final(unsigned char* output_hash_20, const void* msg, int msg_len, int total_length)
{
	int blklen = (((msg_len + 8) >> 6) + 1) * 16;
	int i, off;

	for (i = 0, off = 0; i < blklen; i += 16, off += 16 * 4)
		Transform((unsigned char*)msg + off, msg_len - off, blklen - i, total_length, (int*)output_hash_20);

	for (i = 0; i < 20; i += 4, output_hash_20+=4)
	{
		unsigned char blk[4];
		memcpy(blk, output_hash_20, 4);
		output_hash_20[0] = blk[3];
		output_hash_20[1] = blk[2];
		output_hash_20[2] = blk[1];
		output_hash_20[3] = blk[0];
	}
}

// https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Design_principles

static void Sha1Mix(const unsigned char *msg1, int msg1_len, const unsigned char *msg2, int msg2_len, unsigned char* output20)
{
	int len = msg1_len + msg2_len;
	int blklen = (((len + 8) >> 6) + 1) * 16;

	int h[5] = { 1732584193, -271733879, -1732584194, 271733878, -1009589776 };
	int i, off;

	for (i = 0, off=0; i < blklen; i += 16, off+=16*4)
	{
		if (off + 16 * 4 <= msg1_len)
		{
			Transform(&msg1[off], len - off, blklen - i, len, h);
		}
		else if (off < msg1_len)
		{
			unsigned char temp[16 * 4];
			int l = msg1_len - off;
			memcpy(temp, msg1 + off, l);
			memcpy(&temp[l], msg2, msg2_len <= 16 * 4 - l ? msg2_len : 16 * 4 - l);
			Transform(temp, len - off, blklen - i, len, h);
		}
		else
		{
			Transform(msg2 + (off - msg1_len), len - off, blklen - i, len, h);
		}
	}

	for (i = 0; i < 20; i++)
		output20[i] = h[i / 4] >> (8 * (3 - (i & 3)));
}

void HMAC_Sha1(const unsigned char* key, int key_len, unsigned char* message, int msg_len, unsigned char* output_hash_20)
{
	if (key_len > 64)
	{
		unsigned char key_hash[20];
		Sha1(key, key_len, key_hash);
		HMAC_Sha1(key_hash, 20, message, msg_len, output_hash_20);
	}
	else if (key_len < 64)
	{
		unsigned char temp[64];
		if (key_len > 0)
			memcpy(temp, key, key_len);
		memset(&temp[key_len], 0, 64-key_len);
		HMAC_Sha1(temp, 64, message, msg_len, output_hash_20);
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

		unsigned char i_hash[20];

		Sha1Mix(i_key_pad, 64, message, msg_len, i_hash);
		Sha1Mix(o_key_pad, 64, i_hash, 20, output_hash_20);
	}
}