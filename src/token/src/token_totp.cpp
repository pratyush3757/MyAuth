#include "token_totp.h"

#include "token_hex.h"
#include "token_hotp.h"

#include <cryptopp/filters.h>
#include <cryptopp/base32.h>
#include <cryptopp/hex.h>

#include <string>

static const std::string decodeBase32(const std::string& encoded);

std::string computeTotp(const std::string& secretKey, const long long int time,
                        const int codeDigits,
                        const std::string& hashAlgorithm,
                        const int stepPeriod, 
                        SecretKeyFlags keyEncodingFlags) {
    const long long int timeStep = time/stepPeriod;
    return computeHotp(secretKey, timeStep, codeDigits, hashAlgorithm, keyEncodingFlags);
}

std::string computeTotpFromUri(const std::string& secretKeyBase32, const long long int time,
                        const int codeDigits,
                        const std::string& hashAlgorithm,
                        const int stepPeriod) {
    return computeTotp(decodeBase32(secretKeyBase32), time, codeDigits, hashAlgorithm, stepPeriod, SecretKeyFlags::hex_encoded_secretKey);
}

int computeTotpLifetime(const long long int time, const int stepPeriod) {
    return stepPeriod-(time%stepPeriod);
}

static const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // Most libraries use RFC4648, not CryptoPP.

static const std::string decodeBase32(const std::string& encoded) {
    std::string decoded;

    static int decoding_array[256];
    CryptoPP::Base32Decoder::InitializeDecodingLookupArray(decoding_array, 
                               ALPHABET, 
                               32, 
                               true); // false = case insensitive

    CryptoPP::Base32Decoder b32decoder;
    CryptoPP::AlgorithmParameters dp = CryptoPP::MakeParameters(
                                       CryptoPP::Name::DecodingLookupArray(),
                                       (const int *)decoding_array,
                                       false);
    b32decoder.IsolatedInitialize(dp); 

    b32decoder.Attach(new CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(decoded))
    );
    b32decoder.Put((std::uint8_t*)encoded.c_str(), encoded.size());
    b32decoder.MessageEnd();

    return decoded;
}
