#include "crypto_filehandler.h"

#include "datatypes_secret.h"
#include "datatypes_uri.h"
#include "filesystem_io.h"

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <cryptopp/default.h>
using CryptoPP::DefaultEncryptorWithMAC;
using CryptoPP::DefaultDecryptorWithMAC;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::Redirector;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/hkdf.h>
using CryptoPP::HKDF;

#include <cryptopp/scrypt.h>
using CryptoPP::Scrypt;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <iostream>
#include <fstream>

typedef unsigned char byte;

bool encryptAndWrite(std::map<int, Uri> uriMap,
                     const std::string& dataFile,
                     const std::string& passPhrase) {
    try {        
        if(uriMap.empty()) {
            std::cout << "[Warning] (FileWrite) Datafile is empty." << std::endl;
        }
        
        AutoSeededRandomPool prng;
        FileSink encryptedSink(dataFile.c_str());
        SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);
        SecByteBlock challenge(AES::BLOCKSIZE);
        std::memset(key, 0, key.size());
        std::memset(iv, 0, iv.size());
        std::memset(challenge, 0, challenge.size());
        prng.GenerateBlock(iv, iv.size());
        prng.GenerateBlock(challenge, challenge.size());
        
        Scrypt scrypt;
        //Using IV as salt
        scrypt.DeriveKey(key, key.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                         iv.data(), iv.size());
        
        ArraySource(iv, iv.size(), true, 
                    new HexEncoder(new Redirector(encryptedSink)));
        std::string newline = "\n";
        StringSource(newline, true, new Redirector(encryptedSink));
        
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        ArraySource(challenge, challenge.size(), true,
            new AuthenticatedEncryptionFilter(encryptor,
                new HexEncoder(
                    new Redirector(encryptedSink))));
        StringSource(newline, true, new Redirector(encryptedSink));
        
        for(auto& it:uriMap) {
            std::string clear = it.second.parameters.secretKey;
            it.second.parameters.secretKey.clear();
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            
            StringSource ss1(clear,true,
                new AuthenticatedEncryptionFilter(encryptor,
                    new HexEncoder(
                        new StringSink(it.second.parameters.secretKey))));
            
            std::string line = deriveUriString(it.second);
//             std::cout << line << std::endl;
            StringSource(line, true, new Redirector(encryptedSink));
        }
        encryptedSink.MessageEnd();

        // To enable dynamic key to be set in memory for a new datafile
        std::string ivString;
        ArraySource(iv, iv.size(), true, new HexEncoder(new StringSink(ivString)));
        RuntimeKeys a(passPhrase,ivString);

        //Debug Block
        HexEncoder encoder(new FileSink(std::cout));
        std::cout << "key: ";
        encoder.Put(key, key.size());
        encoder.MessageEnd();
        std::cout << std::endl;
        std::cout << "iv: ";
        encoder.Put(iv, iv.size());
        encoder.MessageEnd();
        std::cout << std::endl;

        return true;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cerr << "[Error] (FileWrite) Save to file Error" << std::endl;
        std::cerr << ex.what() << std::endl;
        return false;
    }
}

bool encryptAndWrite(std::map<int, Uri> uriMap, const std::string& dataFile) {
    try {
        RuntimeKeys dynamicKeyObject;
        SecByteBlock dynamicKey = dynamicKeyObject.getKey();
        SecByteBlock dynamicIv = dynamicKeyObject.getIv();
        
        AutoSeededRandomPool prng;
        FileSink encryptedSink(dataFile.c_str());
        SecByteBlock challenge(AES::BLOCKSIZE);
        prng.GenerateBlock(challenge, challenge.size());
        
        std::string ivString = dynamicKeyObject.getIvData();
        StringSource(ivString, true, new Redirector(encryptedSink));
        std::string newline = "\n";
        StringSource(newline, true, new Redirector(encryptedSink));
        
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(dynamicKey, dynamicKey.size(), dynamicIv, dynamicIv.size());
        
        ArraySource(challenge, challenge.size(), true,
            new AuthenticatedEncryptionFilter(encryptor,
                new HexEncoder(
                    new Redirector(encryptedSink))));
        StringSource(newline, true, new Redirector(encryptedSink));
        
        for(auto it:uriMap) {
            std::string line = deriveUriString(it.second);
            StringSource(line, true, new Redirector(encryptedSink));
        }
        encryptedSink.MessageEnd();
        
        return true;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cerr << ex.what() << std::endl;
        std::cerr << "[Error] (FileWrite) Save to file Error" << std::endl;
        return false;
    }
}

bool decryptAndWrite(std::map<int, Uri> uriMap, const std::string& exportFile) {
    try {
        RuntimeKeys dynamicKeyObject;
        SecByteBlock masterKey = dynamicKeyObject.getKey();
        SecByteBlock masterIv = dynamicKeyObject.getIv();
        
        FileSink decryptedSink(exportFile.c_str());
        
        GCM<AES>::Decryption masterDecryptor;
        masterDecryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
        
        for(auto& it:uriMap) {
            std::string fileSecret = it.second.parameters.secretKey;
            it.second.parameters.secretKey.clear();
            masterDecryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
            
            StringSource ss1(fileSecret, true,
                new HexDecoder(
                    new AuthenticatedDecryptionFilter(masterDecryptor,
                        new StringSink(it.second.parameters.secretKey))));
            
            std::string line = deriveUriString(it.second);
//             std::cout << line << std::endl;
            StringSource(line, true, new Redirector(decryptedSink));
        }
        decryptedSink.MessageEnd();
        
        return true;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cerr << ex.what() << std::endl;
        std::cerr << "[Error] (Export) Save to file Error" << std::endl;
        return false;
    }
}
