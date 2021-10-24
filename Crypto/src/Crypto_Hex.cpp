#include <iomanip>
#include <sstream>
#include <cryptopp/hex.h>

#include "Crypto_Hex.h"

std::string getHex(const long long int counter){
    std::stringstream hexStringStream;

    hexStringStream << std::setfill ('0') << std::setw(16) << std::hex << counter;
    std::string result = hexStringStream.str();

    return result;
}
