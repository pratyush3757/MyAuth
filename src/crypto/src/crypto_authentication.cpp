#include "crypto_authentication.h"

#include "datatypes_secret.h"
#include "filesystem_io.h"

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

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <iostream>

bool authenticatePassPhrase(const std::string& filename, 
                            const std::string& passPhrase) {    
    std::pair<std::string,std::string> tempPair = readIvAndChallenge(filename);
    std::string ivString = tempPair.first;
    std::string challenge = tempPair.second;
 
    RuntimeKeys fileKeys(passPhrase,ivString);
    
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
        std::cerr << "[Error] (Authentication) Authentication Failed!" << std::endl << ex.what() << std::endl;
        return false;
    }
}

