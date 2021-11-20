#ifndef _TOKEN_HOTP_H_
#define _TOKEN_HOTP_H_

std::string computeHotp(const std::string& secretKey, 
                        const long long int counter, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1");

#endif
