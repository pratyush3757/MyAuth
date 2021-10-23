#include <bits/stdc++.h>

#include "Crypto_HMAC.h"
#include "Crypto_IO.h"

int main(){
    std::string mykey = "12345678901234567890";
    std::string msg = "0000000000000007";
    std::cout << "key: " << mykey << std::endl;
    std::cout << "msg: " << msg << std::endl << std::endl;;
    encode_and_print_mac(mykey,"Raw Input key");
    encode_and_print_mac(msg,"Raw Input msg");
    
    std::string macForMd5 = getHmacForGivenAlgorithm(mykey,msg,"MD5");
    encode_and_print_mac(macForMd5,"MD5");
    std::string macForSha1 = getHmacForGivenAlgorithm(mykey,msg,"SHA1");
    encode_and_print_mac(macForSha1,"SHA1");
    std::string macForSha256 = getHmacForGivenAlgorithm(mykey,msg,"SHA256");
    encode_and_print_mac(macForSha256,"SHA256");
    std::string macForSha512 = getHmacForGivenAlgorithm(mykey,msg,"SHA512");
    encode_and_print_mac(macForSha512,"SHA512");
    return 0;
}
