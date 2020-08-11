#include <string>
#include <string.h>
#include <vector>
#include "base64.h"

std::string Base64Encode(const unsigned char* data, int count)
{
	char _base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string text;

	// 0000 0011 - 1111 2222 - 2233 3333

	for (int i = 0; i < count * 8; i += 24)
	{
		unsigned long code = 0;
		int j;

		for (j = 0; j < 3 && i + j * 8 < count * 8; j++)
			code |= ((unsigned long)data[i / 8 + j]) << (24 - 8 - 8 * j);

		for (j = 0; j < 24 && i + j < count * 8; j += 6)
			text.push_back(_base64[(code >> (24 - 6 - j)) & 63]);

		for (; j < 24; j += 6)
			text.push_back('=');
	}
	return text;
}

std::vector <unsigned char> Base64Decode(const char* text, bool url)
{
	static char _base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static char _base64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::vector <unsigned char> bytes;

	const char* _base64table = url == false ? _base64 : _base64url;
	unsigned long data = 0;
	int off = 0;
	for (int i = 0; text[i]; i++)
	{
		const char* p = strchr(_base64table, text[i]);
		if (p != NULL)
		{
			data |= (p - _base64table) << ((3 - (off & 3)) * 6);
			off++;

			if ((off&3) == 0)
			{
				bytes.push_back((data >> 16) & 255);
				bytes.push_back((data >> 8) & 255);
				bytes.push_back(data & 255);
				data = 0;
			}
		}
	}
	// 1111 1122 2222 3333 3300 0000
	if ((off&3) >= 1)
		bytes.push_back((data >> 16) & 255);
	if ((off&3) >= 3)
		bytes.push_back((data >> 8) & 255);
	return bytes;
}