#ifndef _MY_AUTH_H_
#define _MY_AUTH_H_

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/aes.h>

#include <string>
#include <map>
#include <utility>
#include <cstdint>
#include <type_traits>

#ifndef _DATATYPES_FLAGS_H_
#define _DATATYPES_FLAGS_H_

enum class SecretKeyFlags : std::uint8_t {
    ascii_secretKey = 0U << 0,
    base32_encoded_secretKey = 1U << 1,
    encrypted_secretKey = 1U << 0,
    hex_encoded_secretKey = 1U << 2, // For debugging use
    // ...
};

constexpr SecretKeyFlags operator| (SecretKeyFlags lhs, SecretKeyFlags rhs) {
    using underlying_t = typename std::underlying_type<SecretKeyFlags>::type;
 
    return static_cast<SecretKeyFlags>(
        static_cast<underlying_t>(lhs)
        | static_cast<underlying_t>(rhs)
        );
}

constexpr SecretKeyFlags operator& (SecretKeyFlags lhs, SecretKeyFlags rhs) {
    using underlying_t = typename std::underlying_type<SecretKeyFlags>::type;
 
    return static_cast<SecretKeyFlags>(
        static_cast<underlying_t>(lhs)
        | static_cast<underlying_t>(rhs)
        );
}

#endif // _DATATYPES_FLAGS_H_

#ifndef _DATATYPES_SECRET_H_
#define _DATATYPES_SECRET_H_

class RuntimeKeys {
private:
    static SecByteBlock iv;
    static SecByteBlock key;

    SecByteBlock decodeIv(const std::string& ivString);
    SecByteBlock deriveKeyFromPass(const std::string& passPhrase);
    
public:
    RuntimeKeys(){}
    RuntimeKeys(const std::string& passPhrase, const std::string& ivString);
    
    std::string getKeyData();
    std::string getIvData();
    SecByteBlock getKey();
    SecByteBlock getIv();
};

#endif // _DATATYPES_SECRET_H_

#ifndef _DATATYPES_URI_H_
#define _DATATYPES_URI_H_

struct Uri {
public:
    std::string protocol, otpType, labelIssuer, labelAccountName;// queryString;
    
    struct parameters {
        std::string secretKey, issuer, hashAlgorithm, codeDigits, counter, stepPeriod;
    } parameters;

};

Uri parseUriString(const std::string& uri);

std::string deriveUriString(const Uri inputUri);

#endif // _DATATYPES_URI_H_

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

bool authenticatePassPhrase(const std::string& filename, const std::string& passPhrase);

bool encryptAndWrite(std::map<int, Uri> uriMap, const std::string& dataFile);

bool encryptAndWrite(std::map<int, Uri> uriMap, 
                     const std::string& dataFile, 
                     const std::string& passPhrase);

bool decryptAndWrite(std::map<int, Uri> uriMap, const std::string& exportFile);

std::map<int, Uri> runtimeEncrypt(std::map<int, Uri> uriMap, const std::string& passPhrase);

Uri runtimeEncrypt(Uri uriEntry);

#endif // _CRYPTO_H_

#ifndef _FILESYSTEM_IO_H_
#define _FILESYSTEM_IO_H_

std::map<int, Uri> readRawDB(const std::string& filename);

std::map<int, Uri> readAuthDB(const std::string& dataFile, const std::string& passPhrase);

std::pair<std::string,std::string> readIvAndChallenge(const std::string& dataFile);

bool statDataFile(const std::string& dataFile);

std::pair<bool, std::string> findDataFile();

bool updateDatafile(std::map<int, Uri> uriMap,const std::string& dataFile);

#endif // _FILESYSTEM_IO_H_

#ifndef _IMPORT_EXPORT_H_
#define _IMPORT_EXPORT_H_

bool convertToDatafile(const std::string& clearFile,
                       const std::string& dataFile,
                       const std::string& passPhrase);

bool exportRawData(std::map<int,Uri> uriMap, const std::string& exportfile);

#endif // _IMPORT_EXPORT_H_

#ifndef _TOKEN_H_
#define _TOKEN_H_

std::string computeHex(const long long int counter);

std::string computeTotp(const std::string& secretKey, const long long int time, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1", 
                        const int stepPeriod = 30,
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

int computeTotpLifetime(const long long int time, const int stepPeriod);

std::string computeHotp(const std::string& secretKey, 
                        const long long int counter, 
                        const int codeDigits = 6, 
                        const std::string& hashAlgorithm = "SHA1",
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

std::string computeHmac(const std::string& hmacSecretKey, 
                        const std::string& hexEncodedMessage, 
                        const std::string& hashAlgorithm = "SHA1", 
                        SecretKeyFlags keyEncodingFlags=SecretKeyFlags::ascii_secretKey);

#endif // _TOKEN_H_

#endif // _MY_AUTH_H_
