#include <bits/stdc++.h>

#include "token_hmac.h"
#include "token_hotp.h"
#include "token_io.h"

int main() {
    std::string mykey = "12345678901234567890";
    std::string msg = "0000000000000000";
    long long counter = 0;
    std::cout << "key: " << mykey << std::endl;
//     std::cout << "msg: " << msg << std::endl << std::endl;
    std::cout << "Counter\tHOTP" << std::endl;
    for (int i = 0; i < 10; i++, counter++)
        std::cout << counter << '\t' << computeHotp(mykey,counter) << std::endl;

//     encode_and_print_mac(mykey,"Raw Input key");
//     encode_and_print_mac(msg,"Raw Input msg");
//
//     std::string macForMd5 = getHmacForGivenAlgorithm(mykey,msg,"MD5");
//     std::cout << "MD5:\t" << macForMd5 << std::endl;
//     std::cout << "MD5 Size:\t" << macForMd5.size()/2 << std::endl;
//
//     std::string macForSha1 = getHmacForGivenAlgorithm(mykey,msg,"SHA1");
//     std::cout << "SHA1:\t" << macForSha1 << std::endl;
//     std::cout << "SHA1 Size:\t" << macForSha1.size()/2 << std::endl;
//
//     std::string macForSha256 = getHmacForGivenAlgorithm(mykey,msg,"SHA256");
//     std::cout << "SHA256:\t" << macForSha256 << std::endl;
//     std::cout << "SHA256 Size:\t" << macForSha256.size()/2 << std::endl;
//
//     std::string macForSha512 = getHmacForGivenAlgorithm(mykey,msg,"SHA512");
//     std::cout << "SHA512:\t" << macForSha512 << std::endl;
//     std::cout << "SHA512 Size:\t" << macForSha512.size()/2 << std::endl;
    
    return 0;
}
