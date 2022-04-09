#include "fs_io_crypto_filehandler.h"

#include "datatypes_secret.h"
#include "datatypes_uri.h"

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

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/hkdf.h>
using CryptoPP::HKDF;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;

typedef unsigned char byte;

void encryptFile(const std::string& clearFile, 
                 const std::string& encryptedFile, 
                 const std::string& passPhrase) {
    try {
        if(aesEncryptFile(clearFile, encryptedFile, passPhrase)) {
            std::cout << "EncryptFile done";
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
        perror("Encryption Error");
        exit(1);
    }
}

void decryptFile(const std::string& encryptedFile,
                 const std::string& clearFile,
                 const std::string& passPhrase) {
    try {
        if(aesDecryptFile(encryptedFile, clearFile, passPhrase)) {
            std::cout << "DecryptFile done";
//             exit(0);
        }
        else {
            std::cout << "DecryptFile Error";
            exit(1);
        }
//         FileSource f(encryptedFile.c_str(), true,
//                      new DefaultDecryptorWithMAC(
//                          passPhrase.c_str(), new FileSink(clearFile.c_str())));
    }
    catch(...) {
        perror("Decryption Error");
        exit(1);
    }
}

bool aesEncryptFile(const std::string& clearFile,
                    const std::string& encryptedFile,
                    const std::string& passPhrase) {
    try {
        AutoSeededRandomPool prng;
        FileSink encryptedSink(encryptedFile.c_str());
        SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);
        
        std::memset(key, 0, key.size());
        std::memset(iv, 0, iv.size());
        prng.GenerateBlock(iv, iv.size());

        HKDF<SHA256> hkdf;
        //Using IV as salt
        hkdf.DeriveKey(key, key.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                       (const byte*)iv.data(), iv.size(), NULL, 0);

        GCM<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        //Write (IV + Encrypted Data) to file
        ArraySource(iv, iv.size(), true, 
                    new Redirector(encryptedSink));
        FileSource(clearFile.c_str(), true,
            new AuthenticatedEncryptionFilter(encryptor,
                new Redirector(encryptedSink)
            )
        );

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

bool aesDecryptFile(const std::string& encryptedFile, 
                    const std::string& clearFile, 
                    const std::string& passPhrase) {
    try {
        FileSource encryptedSource(encryptedFile.c_str(), false);
        SecByteBlock key(AES::MAX_KEYLENGTH), iv(AES::BLOCKSIZE);
        std::memset(key, 0, key.size());
        std::memset(iv, 0, iv.size());

        //Get IV from file's beginning
        ArraySink ivSink(iv, iv.size());
        encryptedSource.Attach(new Redirector(ivSink));
        encryptedSource.Pump(AES::BLOCKSIZE);
        encryptedSource.Detach();
        
        HKDF<SHA256> hkdf;
        //Using IV as salt
        hkdf.DeriveKey(
            key, key.size(), (const byte*)passPhrase.data(), passPhrase.size(),
            (const byte*)iv.data(), iv.size(), NULL, 0);

        //Debug block
        CryptoPP::HexEncoder encoder(new FileSink(std::cout));
        std::cout << "key: ";
        encoder.Put(key, key.size());
        encoder.MessageEnd();
        std::cout << std::endl;
        std::cout << "iv: ";
        encoder.Put(iv, iv.size());
        encoder.MessageEnd();
        std::cout << std::endl;
        
        GCM<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        encryptedSource.Attach(
            new AuthenticatedDecryptionFilter(
                decryptor, new FileSink(clearFile.c_str())
            )
        );
        encryptedSource.PumpAll();
        encryptedSource.Detach();

        return true;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cout << ex.what() << std::endl;
        return false;
    }
}

bool authenticatePassPhrase(const std::string& filename, const std::string& passPhrase) {
    std::cout << "[Authentication] * trying to open and read: " << filename << std::endl;
    std::ifstream f(filename);
    
    // After this attempt to open a file, we can safely use perror() only  
    // in case f.is_open() returns False.
    if(!f.is_open()) {
        perror(("[Error] (Authentication) error while opening file " + filename).c_str());
        exit(1);
    }
    
    std::string ivString;
    std::string challenge;
    getline(f, ivString);
    getline(f, challenge);
    
    RuntimeKeys fileKeys(passPhrase,ivString);
    
    if(f.bad()) {
        perror(("[Error] (Authentication) error while reading file " + filename).c_str());
        exit(1);
    }   

    f.close();
    
    try {
        CryptoPP::ByteQueue challengesink;
        GCM<AES>::Decryption decryptor;
        SecByteBlock masterKey = fileKeys.getKey();
        SecByteBlock masterIv = fileKeys.getIv();
        decryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
        StringSource(challenge, true, new HexDecoder(
            new AuthenticatedDecryptionFilter(decryptor, new Redirector(challengesink))));
        
        return true;
    }
    catch(const CryptoPP::Exception& ex) {
        std::cerr << "Authentication Failed!" << std::endl << ex.what() << std::endl;
        return false;
    }
}

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
        
        HKDF<SHA256> hkdf;
        //Using IV as salt
        hkdf.DeriveKey(dynamicKey, dynamicKey.size(), (const byte*)passPhrase.data(), passPhrase.size(),
                    (const byte*)dynamicIv.data(), dynamicIv.size(), NULL, 0);
        
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
