#ifndef _CRYPTO_HOTP_H_
#define _CRYPTO_HOTP_H_

std::string computeHotp(const std::string& secretKey, 
                        const long long int counter, 
                        const int codeDigits = 6, 
                        const bool addChecksum = false, 
                        const int truncationOffset = -1, 
                        const std::string& hashAlgorithm = "SHA1");

#endif
