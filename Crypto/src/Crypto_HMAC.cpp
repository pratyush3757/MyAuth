#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/channels.h>
#include <cryptopp/hex.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include "Crypto_HMAC.h"

std::string getHmacForGivenAlgorithm(const std::string& hmacSecretKey, const std::string& hexEncodedMessage,const std::string& algorithm){
    std::string mac;
    
    mac.clear();
    try
    {
        //HMAC Transforms
        CryptoPP::HMAC <CryptoPP::Weak::MD5> hmacMd5((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::HMAC <CryptoPP::SHA1> hmacSha1((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::HMAC <CryptoPP::SHA256> hmacSha256((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        CryptoPP::HMAC <CryptoPP::SHA512> hmacSha512((byte *)hmacSecretKey.c_str(), hmacSecretKey.size());
        
        //Hash Filters
        CryptoPP::HashFilter hashFilterMd5(hmacMd5,new CryptoPP::StringSink(mac));
        CryptoPP::HashFilter hashFilterSha1(hmacSha1,new CryptoPP::StringSink(mac));
        CryptoPP::HashFilter hashFilterSha256(hmacSha256,new CryptoPP::StringSink(mac));
        CryptoPP::HashFilter hashFilterSha512(hmacSha512,new CryptoPP::StringSink(mac));
        
        CryptoPP::ChannelSwitch cs;
        
        if(algorithm=="MD5"){
            cs.AddDefaultRoute(hashFilterMd5);
        }
        else if(algorithm=="SHA1"){
            cs.AddDefaultRoute(hashFilterSha1);
        }
        else if(algorithm=="SHA256"){
            cs.AddDefaultRoute(hashFilterSha256);
        }
        else if(algorithm=="SHA512"){
            cs.AddDefaultRoute(hashFilterSha512);
        }
        
        CryptoPP::StringSource(hexEncodedMessage, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::Redirector(cs)
                )
        );
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
    return mac;
}
