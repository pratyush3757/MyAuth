#include <string>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "Crypto_HOTP.h"
#include "Crypto_HMAC.h"
#include "Crypto_Hex.h"

static bool truncationOffsetIsValid(const int truncationOffset, const int macSizeInBytes){
    return (0 <= truncationOffset) && (truncationOffset < (macSizeInBytes - 4));
}

static int powerOf10(int n)
{
    static const int pow10[10] = {
        1, 10, 100, 1000, 10000,
        100000, 1000000, 10000000, 100000000, 1000000000
    };

    return pow10[n];
}

static int calculateCardChecksum(long num, const int digits){
    //TODO: Implement the checksum function
    return 0;
}

static void padZeros(std::string& zeroPaddedHotp, const int digits){
    const char paddingChar = '0';
    if(digits > zeroPaddedHotp.size())
        zeroPaddedHotp.insert(0,digits-zeroPaddedHotp.size(),paddingChar);
}

std::string getHotp(const std::string& secretKey, const long long counter, const int codeDigits, const bool addChecksum, const int truncationOffset, const std::string& hashAlgorithm){
    const std::string hexEncodedCounter = getHex(counter);

    const int totalDigits = addChecksum ? (codeDigits + 1) : codeDigits;

    const std::string hexEncodedMac = getHmacForGivenAlgorithm(secretKey, hexEncodedCounter, hashAlgorithm);
    const int macSizeInBytes = hexEncodedMac.size()/2;

    std::vector<CryptoPP::byte> macArray;
    macArray.resize(macSizeInBytes);

    CryptoPP::StringSource(hexEncodedMac, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(&macArray[0],macSizeInBytes)
            )
    );

    int offset = macArray[macSizeInBytes - 1] & 0xf;
    if (truncationOffsetIsValid(truncationOffset, macSizeInBytes)){
        offset = truncationOffset;
    }

    int truncatedDecimalOtp = ((macArray[offset] & 0x7f) << 24)
                            | ((macArray[offset + 1] & 0xff) << 16)
                            | ((macArray[offset + 2] & 0xff) << 8)
                            | (macArray[offset + 3] & 0xff);

    int hotp = truncatedDecimalOtp % powerOf10(codeDigits);

    if (addChecksum){
        hotp = (hotp*10) + calculateCardChecksum(hotp,codeDigits);
    }

    std::string zeroPaddedHotp = std::to_string(hotp);
    padZeros(zeroPaddedHotp,totalDigits);

    return zeroPaddedHotp;
}
