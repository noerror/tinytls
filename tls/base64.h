#ifndef _BASE64_H
#define _BASE64_H

#include <string>
#include <vector>

std::string Base64Encode(const unsigned char* data, int count);
std::vector <unsigned char> Base64Decode(const char* text, bool url=false);

#endif