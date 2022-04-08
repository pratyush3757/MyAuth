#include "datatypes_secret.h"

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::StringSource;
using CryptoPP::StringSink;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;

#include <cryptopp/hkdf.h>
using CryptoPP::HKDF;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <string>
#include <iostream>

typedef unsigned char byte;

SecByteBlock RuntimeKeys::iv(CryptoPP::AES::BLOCKSIZE);
SecByteBlock RuntimeKeys::key(CryptoPP::AES::MAX_KEYLENGTH);

SecByteBlock RuntimeKeys::decodeIv(const std::string& ivString) {
    SecByteBlock decodedIv;
    decodedIv.resize(AES::BLOCKSIZE);
    StringSource(ivString, true, new HexDecoder(new ArraySink(decodedIv, decodedIv.size())));
    return decodedIv;
}

SecByteBlock RuntimeKeys::deriveKeyFromPass(const std::string& passPhrase) {
    SecByteBlock derivedKey;
    derivedKey.resize(AES::MAX_KEYLENGTH);
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derivedKey, derivedKey.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                   (const byte*)iv.data(), iv.size(), NULL, 0);
        
    return derivedKey;
}

RuntimeKeys::RuntimeKeys(const std::string& passPhrase, const std::string& ivString) {
    this->iv.Assign(decodeIv(ivString));    
    this->key.Assign(deriveKeyFromPass(passPhrase));
    //Debug block
//     std::cout << "Key Generated" << std::endl 
//     << "Key: " << this->getKeyData() << std::endl 
//     << "IV: " << this->getIvData() << std::endl;
}

std::string RuntimeKeys::getKeyData() {
    std::string str;
    CryptoPP::HexEncoder encoder(new StringSink(str));
    encoder.Put(key,key.size());
    encoder.MessageEnd();
    return str;
}
    
std::string RuntimeKeys::getIvData() {
    std::string str;
    CryptoPP::HexEncoder encoder(new StringSink(str));
    encoder.Put(iv,iv.size());
    encoder.MessageEnd();
    return str;        
}

SecByteBlock RuntimeKeys::getKey() {
    return key;
}
SecByteBlock RuntimeKeys::getIv() {
    return iv;
}
