#include "token_hotp.h"

#include "token_hmac.h"
#include "token_hex.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <string>

static int getPowerOf10(int n) {
    static const int pow10[10] = {
        1, 10, 100, 1000, 10000,
        100000, 1000000, 10000000, 100000000, 1000000000
    };

    return pow10[n];
}

static void padZerosTowardsLeft(std::string& zeroPaddedHotp, const int digits) {
    const char paddingChar = '0';

    if(digits > zeroPaddedHotp.size())
        zeroPaddedHotp.insert(0, digits-zeroPaddedHotp.size(), paddingChar);
}

std::string computeHotp(const std::string& secretKey, const long long int counter,
                        const int codeDigits,
                        const std::string& hashAlgorithm,
                        SecretKeyFlags keyEncodingFlags) {
    const std::string hexEncodedCounter = computeHex(counter);
    const std::string hexEncodedMac = computeHmacForGivenAlgorithm(
                                      secretKey, hexEncodedCounter,
                                      hashAlgorithm, keyEncodingFlags);

    const int macSizeInBytes = hexEncodedMac.size() / 2;
    std::vector<CryptoPP::byte> macByteArray;
    macByteArray.resize(macSizeInBytes);

    CryptoPP::StringSource(hexEncodedMac, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(&macByteArray[0], macSizeInBytes)
        )
    );

    int offset = macByteArray[macSizeInBytes - 1] & 0xf;

    int truncatedDecimalOtp = ((macByteArray[offset] & 0x7f) << 24)
                            | ((macByteArray[offset + 1] & 0xff) << 16)
                            | ((macByteArray[offset + 2] & 0xff) << 8)
                            | (macByteArray[offset + 3] & 0xff);

    int hotp = truncatedDecimalOtp % getPowerOf10(codeDigits);


    std::string zeroPaddedHotp = std::to_string(hotp);
    padZerosTowardsLeft(zeroPaddedHotp, codeDigits);

    return zeroPaddedHotp;
}
