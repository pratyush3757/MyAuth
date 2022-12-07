#ifndef _TOKEN_TOTP_H_
#define _TOKEN_TOTP_H_

#include "datatypes_flags.h"
#include <string>

std::string computeTotp(const std::string& secretKey, const long long int time, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1", 
                        const int stepPeriod = 30,
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

int computeTotpLifetime(const long long int time, const int stepPeriod);

#endif
