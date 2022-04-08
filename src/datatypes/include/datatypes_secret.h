#ifndef _DATATYPES_SECRET_H_
#define _DATATYPES_SECRET_H_

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/aes.h>

#include <string>

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

#endif
