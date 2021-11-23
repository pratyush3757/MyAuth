#include "token_hex.h"

#include <cryptopp/hex.h>

#include <iomanip>
#include <sstream>

std::string computeHex(const long long int counter) {
    std::stringstream hexStringStream;

    hexStringStream << std::setfill ('0') << std::setw(16) << std::hex << counter;
    std::string result = hexStringStream.str();

    return result;
}
