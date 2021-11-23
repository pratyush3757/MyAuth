#ifndef _TOKEN_HMAC_BYTE_H_
#define _TOKEN_HMAC_BYTE_H_

#include <string>

std::string computeHmacForGivenAlgorithm(const std::string& hmacSecretKey, 
                                         const std::string& hexEncodedMessage, 
                                         const std::string& hashAlgorithm = "SHA1", 
                                         bool nonAsciiKey = false);

#endif
