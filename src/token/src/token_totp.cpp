#include <string>

#include "token_totp.h"
#include "token_hex.h"
#include "token_hotp.h"

std::string computeTotp(const std::string& secretKey, const long long int time,
                        const int codeDigits,
                        const std::string& hashAlgorithm,
                        const int period) {
    const long long int timeStep = time/period;
    return computeHotp(secretKey,timeStep,codeDigits,hashAlgorithm);
}

int computeTotpLifetime(const long long int time, const int period){
    return time%period;
}
