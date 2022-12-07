#include "crypto_runtime.h"

#include "datatypes_uri.h"
#include "datatypes_secret.h"

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::Redirector;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/scrypt.h>
using CryptoPP::Scrypt;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <iostream>

typedef unsigned char byte;
/*
void importFile(const std::string& clearFile, 
                const std::string& encryptedFile, 
                const std::string& passPhrase) {
    if(importRawFile(clearFile, encryptedFile, passPhrase)) {
        std::cout << "[Info] (Import) File Import Encryption done" << std::endl;
    }
    else {
        exit(1);
    }
}*/


std::map<int, Uri> runtimeEncrypt(std::map<int, Uri> uriMap, const std::string& passPhrase) {
//  Take the encrypted data from file, decrypt it and re-encrypt it to a new dynamic key.
//  The key stored in RuntimeKeys is the file key at first, which is overwritten by the dynamic key at the end.
    if(uriMap.empty()) {
        return uriMap;
    }

    try {
        RuntimeKeys fileKeys;
        SecByteBlock masterKey = fileKeys.getKey();
        SecByteBlock masterIv = fileKeys.getIv();
                
        GCM<AES>::Decryption masterDecryptor;
        masterDecryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
        
        AutoSeededRandomPool prng;
        SecByteBlock dynamicKey(AES::MAX_KEYLENGTH), dynamicIv(AES::BLOCKSIZE);
        std::memset(dynamicKey, 0, dynamicKey.size());
        std::memset(dynamicIv, 0, dynamicIv.size());
        prng.GenerateBlock(dynamicIv, dynamicIv.size());
        
        Scrypt scrypt;
        //Using IV as salt
        scrypt.DeriveKey(dynamicKey, dynamicKey.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                         dynamicIv.data(), dynamicIv.size());
        
        std::string dynamicIvString;
        ArraySource(dynamicIv, dynamicIv.size(), true, 
                        new CryptoPP::HexEncoder(new StringSink(dynamicIvString)));
        
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(dynamicKey, dynamicKey.size(), dynamicIv, dynamicIv.size());
        
        for(auto& it:uriMap) {
            std::string fileSecret = it.second.parameters.secretKey;
            it.second.parameters.secretKey.clear();
            encryptor.SetKeyWithIV(dynamicKey, dynamicKey.size(), dynamicIv, dynamicIv.size());
            masterDecryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
            
            CryptoPP::StringSource ss1(fileSecret, true,
                new HexDecoder(
                    new AuthenticatedDecryptionFilter(masterDecryptor,
                        new AuthenticatedEncryptionFilter(encryptor,
                            new CryptoPP::HexEncoder(
                                new CryptoPP::StringSink(it.second.parameters.secretKey))))));
        }
        RuntimeKeys dynamicKeys(passPhrase, dynamicIvString);
        return uriMap;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cout << ex.what() << std::endl;
        exit(1);
    }
    return uriMap;
}

Uri runtimeEncrypt(Uri uriEntry) {
    try {
        RuntimeKeys dynamicKeys;
        SecByteBlock masterKey = dynamicKeys.getKey();
        SecByteBlock masterIv = dynamicKeys.getIv();
        
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
        
        std::string clear = uriEntry.parameters.secretKey;
        uriEntry.parameters.secretKey.clear();
        
        StringSource ss1(clear,true,
            new AuthenticatedEncryptionFilter(encryptor,
                new HexEncoder(
                    new StringSink(uriEntry.parameters.secretKey))));
    }
    catch(const CryptoPP::Exception& ex) {
        std::cout << ex.what() << std::endl;
        exit(1);
    }
    
    return uriEntry;
}
