#ifndef _TOKEN_HMAC_BYTE_H_
#define _TOKEN_HMAC_BYTE_H_

#include "datatypes_flags.h"
#include <string>

// std::string computeHmacForGivenAlgorithm(const std::string& hmacSecretKey, 
//                                          const std::string& hexEncodedMessage, 
//                                          const std::string& hashAlgorithm = "SHA1", 
//                                          bool nonAsciiKey = false);

std::string computeHmacForGivenAlgorithm(const std::string& hmacSecretKey, 
                                         const std::string& hexEncodedMessage, 
                                         const std::string& hashAlgorithm = "SHA1", 
                                         SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

#endif
