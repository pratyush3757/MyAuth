#ifndef _DATATYPE_URI_
#define _DATATYPE_URI_

#include <string>

struct Uri {
public:
    std::string protocol, otpType, labelIssuer, labelAccountName;// queryString;
    
    struct parameters {
        std::string secretKey, issuer, hashAlgorithm, codeDigits, counter, stepPeriod;
    } parameters;

};

#endif
