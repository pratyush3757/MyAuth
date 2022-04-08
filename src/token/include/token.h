#ifndef _TOKEN_H_
#define _TOKEN_H_

#include "datatypes_flags.h"
#include <string>

std::string computeHex(const long long int counter);

std::string computeTotp(const std::string& secretKey, const long long int time, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1", 
                        const int stepPeriod = 30,
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

std::string computeTotpFromUri(const std::string& secretKeyBase32, const long long int time,
                        const int codeDigits = 6,
                        const std::string& hashAlgorithm = "SHA1",
                        const int stepPeriod = 30);

int computeTotpLifetime(const long long int time, const int stepPeriod);

std::string computeHotp(const std::string& secretKey, 
                        const long long int counter, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1",
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

std::string computeHmacForGivenAlgorithm(const std::string& hmacSecretKey, 
                                         const std::string& hexEncodedMessage, 
                                         const std::string& hashAlgorithm = "SHA1", 
                                         SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

void encodeAndPrintMac(std::string decodedMac, std::string hashAlgorithm);

void decode_and_print_key(std::string encodedKey);

#endif
