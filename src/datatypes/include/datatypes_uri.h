#ifndef _DATATYPES_URI_H_
#define _DATATYPES_URI_H_

#include <string>

struct Uri {
public:
    std::string protocol, otpType, labelIssuer, labelAccountName;// queryString;
    
    struct parameters {
        std::string secretKey, issuer, hashAlgorithm, codeDigits, counter, stepPeriod;
    } parameters;

};

Uri parseUriString(const std::string& uri);

std::string deriveUriString(const Uri inputUri);

#endif
