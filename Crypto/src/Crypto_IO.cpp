#include <iostream>
#include <cryptopp/hex.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

#include "Crypto_IO.h"

void encode_and_print_mac(std::string decoded_mac,std::string algorithm){
    std::string encoded_mac;
    try
    {
        CryptoPP::StringSource(decoded_mac, true,
                    new CryptoPP::Base32Encoder(
                            new CryptoPP::StringSink(encoded_mac)
                    )            
            );
        std::cout << algorithm << " Base32: " << encoded_mac << std::endl;
        /*
        encoded_mac.clear();
        CryptoPP::StringSource(decoded_mac, true,
                    new CryptoPP::Base64Encoder(
                            new CryptoPP::StringSink(encoded_mac)
                    )            
            );
        std::cout << algorithm << " Base64: " << encoded_mac << std::endl;
        *//*
        encoded_mac.clear();
        CryptoPP::StringSource(decoded_mac, true,
                    new CryptoPP::HexDecoder(
                            new CryptoPP::StringSink(encoded_mac)
                    )            
            );
        std::cout << algorithm << " Decoded Hex: " << encoded_mac << std::endl;*/
        encoded_mac.clear();
        CryptoPP::StringSource(decoded_mac, true,
                    new CryptoPP::HexEncoder(
                            new CryptoPP::StringSink(encoded_mac)
                    )            
            );
        std::cout << algorithm << " Encoded Hex: " << encoded_mac << std::endl;
        std::cout << std::endl;
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    }
}
// This function has something wrong
void decode_and_print_key(std::string encoded_key){
    std::string base32_decoded_key,hex_encoded_key;
    try
    {
        base32_decoded_key.clear();
        CryptoPP::StringSource(encoded_key, true,
                    new CryptoPP::Base32Decoder(
                            new CryptoPP::StringSink(base32_decoded_key)
                    )            
            );
        
        hex_encoded_key.clear();
        CryptoPP::StringSource(base32_decoded_key, true,
                    new CryptoPP::HexEncoder(
                            new CryptoPP::StringSink(hex_encoded_key)
                    )            
            );
        std::cout << "Hex encoded key : " << hex_encoded_key << std::endl << std::endl;
    }
    catch(const CryptoPP::Exception& e){
        std::cerr << e.what() << std::endl;
    };
}
