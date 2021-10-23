#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include "Crypto_HMAC.h"

static std::string getHmacMd5(const std::string& hmacSecretKey, const std::string& hexEncodedMessage){
    std::string mac;
    
    mac.clear();
    try
    {
        
        CryptoPP::HMAC <CryptoPP::Weak::MD5> hmac((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::StringSource(hexEncodedMessage, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::HashFilter(hmac,
                        new CryptoPP::StringSink(mac)
                    )
                )
        );
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
    return mac;
}

static std::string getHmacSha1(const std::string& hmacSecretKey, const std::string& hexEncodedMessage){
    std::string mac;

    mac.clear();
    try
    {
        
        CryptoPP::HMAC <CryptoPP::SHA1> hmac((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::StringSource(hexEncodedMessage, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::HashFilter(hmac,
                        new CryptoPP::StringSink(mac)
                    )
                )
        );
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
    return mac;
}

static std::string getHmacSha256(const std::string& hmacSecretKey, const std::string& hexEncodedMessage){
    std::string mac;

    mac.clear();
    try
    {
        
        CryptoPP::HMAC <CryptoPP::SHA256> hmac((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::StringSource(hexEncodedMessage, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::HashFilter(hmac,
                        new CryptoPP::StringSink(mac)
                    )
                )
        );
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
    return mac;
}

static std::string getHmacSha512(const std::string& hmacSecretKey, const std::string& hexEncodedMessage){
    std::string mac;

    mac.clear();
    try
    {
        
        CryptoPP::HMAC <CryptoPP::SHA512> hmac((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::StringSource(hexEncodedMessage, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::HashFilter(hmac,
                        new CryptoPP::StringSink(mac)
                    )
                )
        );
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
    return mac;
}

std::string getHmacForGivenAlgorithm(const std::string& hmacSecretKey, const std::string& hexEncodedMessage,const std::string& algorithm){
    if(algorithm == "MD5")
        return getHmacMd5(hmacSecretKey,hexEncodedMessage);
    if(algorithm == "SHA1")
        return getHmacSha1(hmacSecretKey,hexEncodedMessage);
    if(algorithm == "SHA256")
        return getHmacSha256(hmacSecretKey,hexEncodedMessage);
    if(algorithm == "SHA512")
        return getHmacSha512(hmacSecretKey,hexEncodedMessage);
    return "";
}
