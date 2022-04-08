#include "datatypes_secret.h"

#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include <iostream>

int main(int argc,char* argv[]) {
    std::string passPhrase, ivString;
    if(argc==3){
        passPhrase = argv[1];
        ivString = argv[2];
    }
    else {
        std::cout << "Invalid/Missing Parameters." << std::endl <<
        "Usage:./datatypes_test <Passphrase> <Hex Encoded IV>"<< std::endl;
        exit(1);
    }
    RuntimeKeys a(passPhrase,ivString);
    RuntimeKeys b;
    std::string key = b.getKeyData();
    std::string iv = b.getIvData();
    
    std::cout << "KEY: " << key << std::endl << "IV: " << iv <<std::endl;
//     std::string str(reinterpret_cast<const char*>(&key[0]), key.size());
//     std::string str2(reinterpret_cast<const char*>(&iv[0]), iv.size());
//     std::cout << std::endl;
//     
//     CryptoPP::HexEncoder encoder(new FileSink(std::cout));
//         std::cout << "key: ";
//         encoder.Put(key, key.size());
//         encoder.MessageEnd();
//         std::cout << std::endl;
//         std::cout << "iv: ";
//         encoder.Put(iv, iv.size());
//         encoder.MessageEnd();
//         std::cout << std::endl;

    //KEY:  35EE6E63B162118E3E0E798C936B5898F799582C2662FCFF8201FB677ABF693B
    //IV:   6EBD2A18838BD291513559E2BBD08464
    return 0;
}
