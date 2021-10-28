#include <iostream>

#include <cryptopp/hex.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

#include "token_io.h"

void encodeAndPrintMac(std::string decodedMac,std::string hashAlgorithm) {
    std::string encodedMac;
    try {
        CryptoPP::StringSource(decodedMac, true,
            new CryptoPP::Base32Encoder(
                new CryptoPP::StringSink(encodedMac)
            )
        );
        std::cout << hashAlgorithm << " Base32: " << encodedMac << std::endl;
        
        encodedMac.clear();
        CryptoPP::StringSource(decodedMac, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(encodedMac)
            )
        );
        std::cout << hashAlgorithm << " Encoded Hex: " << encodedMac << std::endl;
        std::cout << std::endl;
    }
    catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

void decode_and_print_key(std::string encodedKey) {
    std::string base32DecodedKey,hexEncodedKey;
    try {
        base32DecodedKey.clear();
        CryptoPP::StringSource(encodedKey, true,
            new CryptoPP::Base32Decoder(
                new CryptoPP::StringSink(base32DecodedKey)
            )
        );

        hexEncodedKey.clear();
        CryptoPP::StringSource(base32DecodedKey, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hexEncodedKey)
            )
        );
        std::cout << "Hex encoded key : " << hexEncodedKey << std::endl << std::endl;
    }
    catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
    }
}
