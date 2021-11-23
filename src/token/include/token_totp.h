#ifndef _TOKEN_TOTP_H_
#define _TOKEN_TOTP_H_

#include <string>

std::string computeTotp(const std::string& secretKey, const long long int time, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1", 
                        const int stepPeriod = 30,
                        bool nonAsciiKey = false);

std::string computeTotpFromUri(const std::string& secretKeyBase32, const long long int time,
                        const int codeDigits = 6,
                        const std::string& hashAlgorithm = "SHA1",
                        const int stepPeriod = 30);

int computeTotpLifetime(const long long int time, const int stepPeriod);

#endif
