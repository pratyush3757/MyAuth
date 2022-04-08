#include "fs_io_crypto_filehandler.h"

#include "datatypes_secret.h"

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <cryptopp/default.h>
using CryptoPP::DefaultEncryptorWithMAC;
using CryptoPP::DefaultDecryptorWithMAC;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
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
    CryptoPP::ByteQueue challengesink;
    getline(f, ivString);
    
    getline(f, challenge);
    
    RuntimeKeys fileKeys(passPhrase,ivString);
    
    if(f.bad()) {
        perror(("[Error] (Authentication) error while reading file " + filename).c_str());
        exit(1);
    }   

    f.close();
    
    try {
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
