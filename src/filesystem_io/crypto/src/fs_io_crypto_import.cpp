#include "fs_io_crypto_import.h"

#include "datatypes_uri.h"
// #include "datatypes_secret.h"
#include "filesystem_io.h"

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <cryptopp/default.h>
using CryptoPP::DefaultEncryptorWithMAC;
using CryptoPP::DefaultDecryptorWithMAC;

#include <cryptopp/filters.h>
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::Redirector;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/hkdf.h>
using CryptoPP::HKDF;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/hex.h>

typedef unsigned char byte;

void importFile(const std::string& clearFile, 
                const std::string& encryptedFile, 
                const std::string& passPhrase) {
    try {
        if(importRawFile(clearFile, encryptedFile, passPhrase)) {
            std::cout << "EncryptFile done" << std::endl;
            exit(0);
        }
        else {
            exit(1);
        }
//         FileSource f(clearFile.c_str(), true, 
//                      new DefaultEncryptorWithMAC(
//                          passPhrase.c_str(), new FileSink(encryptedFile.c_str())));
//         exit(0);
    }
    catch(...) {
        perror("Import Error");
        exit(1);
    }
}

bool importRawFile(const std::string& clearFile,
                   const std::string& encryptedFile,
                   const std::string& passPhrase) {
    try {
        std::map<int, Uri> fileDataMap = readAuthDB(clearFile);
        
        if(fileDataMap.empty()) {
            std::cout << "[Warning] Datafile is empty." << std::endl;
        }
        
        AutoSeededRandomPool prng;
        FileSink encryptedSink(encryptedFile.c_str());
        SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);
        SecByteBlock challenge(AES::BLOCKSIZE);
        std::memset(key, 0, key.size());
        std::memset(iv, 0, iv.size());
        std::memset(challenge, 0, challenge.size());
        prng.GenerateBlock(iv, iv.size());
        prng.GenerateBlock(challenge, challenge.size());
        
        HKDF<SHA256> hkdf;
        //Using IV as salt
        hkdf.DeriveKey(key, key.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                       (const byte*)iv.data(), iv.size(), NULL, 0);

        ArraySource(iv, iv.size(), true, 
                    new CryptoPP::HexEncoder(new Redirector(encryptedSink)));
        std::string newline = "\n";
        CryptoPP::StringSource(newline, true, new Redirector(encryptedSink));
        
        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        CryptoPP::ArraySource(challenge, challenge.size(), true,
            new AuthenticatedEncryptionFilter(encryptor,
                new CryptoPP::HexEncoder(
                    new Redirector(encryptedSink))));
        CryptoPP::StringSource(newline, true, new Redirector(encryptedSink));
        
        for(auto it:fileDataMap) {
            std::string clear = it.second.parameters.secretKey;
            it.second.parameters.secretKey.clear();
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            
            CryptoPP::StringSource ss1(clear,true,
                new AuthenticatedEncryptionFilter(encryptor,
                    new CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(it.second.parameters.secretKey))));
            
            std::string line = deriveUriString(it.second);
            std::cout << line << std::endl;
            CryptoPP::StringSource(line, true, new Redirector(encryptedSink));
        }
        encryptedSink.MessageEnd();
//         //Write (IV + Encrypted Data) to file
//         FileSource(clearFile.c_str(), true,
//             new AuthenticatedEncryptionFilter(encryptor,
//                 new Redirector(encryptedSink)
//             )
//         );

        //Debug Block
        CryptoPP::HexEncoder encoder(new FileSink(std::cout));
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
        std::cout << ex.what() << std::endl;
        return false;
    }
}
