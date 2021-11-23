#ifndef _FILESYSTEM_IO_UI_H_
#define _FILESYSTEM_IO_UI_H_

#include <string>

struct Uri {
public:
    std::string protocol, otpType, labelIssuer, labelAccountName;// queryString;
    
    struct parameters {
        std::string secretKey, issuer, hashAlgorithm, codeDigits, counter, stepPeriod;
    } parameters;

};

Uri parseUri(const std::string &uri);

#endif
