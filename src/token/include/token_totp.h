#ifndef _TOKEN_TOTP_H_
#define _TOKEN_TOTP_H_

std::string computeTotp(const std::string& secretKey, const long long int time,
                        const int codeDigits = 6,
                        const std::string& hashAlgorithm = "SHA1",
                        const int period = 30);

int computeTotpLifetime(const long long int time, const int period);

#endif
