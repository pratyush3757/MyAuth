#ifndef _CRYPTO_HMAC_BYTE_H_
#define _CRYPTO_HMAC_BYTE_H_

typedef unsigned char byte;

std::string getHmacForGivenAlgorithm(const std::string& hmacSecretKey, const std::string& hexEncodedMessage, const std::string& algorithm = "SHA1");

#endif
