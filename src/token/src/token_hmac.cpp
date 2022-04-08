#include "token_hmac.h"
#include "datatypes_secret.h"

#include <cryptopp/cryptlib.h> //includes CryptoPP::Exception

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::HashFilter;
using CryptoPP::Redirector;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/channels.h>
using CryptoPP::ChannelSwitch;

#include <cryptopp/hmac.h>
using CryptoPP::HMAC;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/base32.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <iostream>
#include <vector>

typedef unsigned char byte;

static const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // Most libraries use RFC4648, not CryptoPP.

static const std::string decodeBase32(const std::string& encoded);
static const ByteQueue decodeSecretKey(const std::string& hmacSecretKey,
                                       SecretKeyFlags keyEncodingFlags);

std::string computeHmacForGivenAlgorithm(const std::string& hmacSecretKey,
                                         const std::string& hexEncodedMessage,
                                         const std::string& hashAlgorithm,
                                         SecretKeyFlags keyEncodingFlags) {
    std::string mac;
    mac.clear();
    try {
        ByteQueue hmacKeySecByte = decodeSecretKey(hmacSecretKey,keyEncodingFlags);
        
        std::vector<byte> hmacSecretKeyVector;
        int hmacVectorSize = hmacKeySecByte.MaxRetrievable();
        hmacSecretKeyVector.resize(hmacVectorSize);
        ArraySink vectorSink(&hmacSecretKeyVector[0], hmacVectorSize);
        hmacKeySecByte.TransferTo(vectorSink);
        
//         if(keyEncodingFlags==SecretKeyFlags::hex_encoded_secretKey) {
//             StringSource ss(hmacSecretKey, true,
//                 new HexDecoder(
//                     new ArraySink(&hmacSecretKeyVector[0], hmacVectorSize)
//                 )
//             );
//         }
//         else {
//             StringSource ss(hmacSecretKey, true,
// //                 new CryptoPP::HexDecoder(
//                     new ArraySink(&hmacSecretKeyVector[0], hmacVectorSize)
// //                 )
//             );
//         }
        
        //HMAC Transforms
        HMAC<CryptoPP::Weak::MD5> hmacMd5(
            &hmacSecretKeyVector[0], hmacSecretKeyVector.size());
        HMAC<SHA1> hmacSha1(
            &hmacSecretKeyVector[0], hmacSecretKeyVector.size());
        HMAC<SHA256> hmacSha256(
            &hmacSecretKeyVector[0], hmacSecretKeyVector.size());
        HMAC<SHA512> hmacSha512(
            &hmacSecretKeyVector[0], hmacSecretKeyVector.size());

        //Hash Filters
        HashFilter hashFilterMd5(
            hmacMd5, new HexEncoder(new StringSink(mac), false));
        HashFilter hashFilterSha1(
            hmacSha1, new HexEncoder(new StringSink(mac), false));
        HashFilter hashFilterSha256(
            hmacSha256, new HexEncoder(new StringSink(mac), false));
        HashFilter hashFilterSha512(
            hmacSha512, new HexEncoder(new StringSink(mac), false));

        ChannelSwitch cs;

        if(hashAlgorithm=="MD5") {
            cs.AddDefaultRoute(hashFilterMd5);
        }
        else if(hashAlgorithm=="SHA1") {
            cs.AddDefaultRoute(hashFilterSha1);
        }
        else if(hashAlgorithm=="SHA256") {
            cs.AddDefaultRoute(hashFilterSha256);
        }
        else if(hashAlgorithm=="SHA512") {
            cs.AddDefaultRoute(hashFilterSha512);
        }

        StringSource(hexEncodedMessage, true,
            new HexDecoder(
                new Redirector(cs)
            )
        );
        // Zeroing the vector
        hmacSecretKeyVector.assign(hmacSecretKeyVector.size(), 0);
    }
    catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return mac;
}

static const std::string decodeBase32(const std::string& encoded) {
    std::string decoded;

    static int decoding_array[256];
    CryptoPP::Base32Decoder::InitializeDecodingLookupArray(decoding_array, 
                               ALPHABET, 
                               32, 
                               true); // false = case insensitive

    CryptoPP::Base32Decoder b32decoder;
    CryptoPP::AlgorithmParameters dp = CryptoPP::MakeParameters(
                                       CryptoPP::Name::DecodingLookupArray(),
                                       (const int *)decoding_array,
                                       false);
    b32decoder.IsolatedInitialize(dp); 

    b32decoder.Attach(new CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(decoded))
    );
    b32decoder.Put((std::uint8_t*)encoded.c_str(), encoded.size());
    b32decoder.MessageEnd();

    return decoded;
}

static const ByteQueue decodeSecretKey(const std::string& hmacSecretKey,
                                       SecretKeyFlags keyEncodingFlags) {
    ByteQueue encodedKeySecByte, hmacSecByte;
    encodedKeySecByte.Put(reinterpret_cast<const byte*>(&hmacSecretKey[0]), hmacSecretKey.size());
    
    if(keyEncodingFlags==SecretKeyFlags::ascii_secretKey) {
        encodedKeySecByte.TransferTo(hmacSecByte);
    }
    else if(keyEncodingFlags==SecretKeyFlags::hex_encoded_secretKey) {
        HexDecoder decoder(new Redirector(hmacSecByte));
    }
    else {
        if(keyEncodingFlags==SecretKeyFlags::encrypted_secretKey) {
            RuntimeKeys masterKeyData;
            ByteQueue intermediateSecByte;
            
            SecByteBlock masterKey = masterKeyData.getKey();
            SecByteBlock masterIv = masterKeyData.getIv();
            
// //             std::cout <<"\nKey: "<< masterKeyData.getKeyData() <<std::endl<<"IV: "<<masterKeyData.getIvData()<<std::endl;
            
            encodedKeySecByte.Clear();
            StringSource(hmacSecretKey,true,new HexDecoder(new Redirector(encodedKeySecByte)));
            
            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(masterKey, masterKey.size(), masterIv, masterIv.size());
            
            AuthenticatedDecryptionFilter ad(decryptor, new Redirector(intermediateSecByte));
            encodedKeySecByte.TransferTo(ad);
            ad.MessageEnd();
            intermediateSecByte.TransferTo(encodedKeySecByte);
        }
        // keyEncodingFlags==SecretKeyFlags::base32_encoded_secretKey
        static int decoding_array[256];
        CryptoPP::Base32Decoder::InitializeDecodingLookupArray(decoding_array, 
                                                               ALPHABET,
                                                               32,
                                                               true); // false = case insensitive

        CryptoPP::Base32Decoder b32decoder;
        CryptoPP::AlgorithmParameters dp = CryptoPP::MakeParameters(
            CryptoPP::Name::DecodingLookupArray(),
            (const int *)decoding_array,
            false);
        b32decoder.IsolatedInitialize(dp);
        b32decoder.Attach(new Redirector(hmacSecByte));
        encodedKeySecByte.TransferTo(b32decoder);
        b32decoder.MessageEnd();
    }
    
    return hmacSecByte;
}
