#ifndef _TOKEN_HOTP_H_
#define _TOKEN_HOTP_H_

#include "datatypes_flags.h"
#include <string>

std::string computeHotp(const std::string& secretKey, 
                        const long long int counter, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1",
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

#endif
