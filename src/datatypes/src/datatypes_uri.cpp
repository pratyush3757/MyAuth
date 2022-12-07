#include "datatypes_uri.h"

#include <iostream>
#include <map>
#include <algorithm>    // find
#include <sstream>

static std::map<std::string, std::string> split_query(const std::string& query);

Uri parseUriString(const std::string& uri) {
    Uri result;

    typedef std::string::const_iterator iterator_t;

    if(uri.length() == 0) {
        return result;
    }

    iterator_t uriEnd = uri.end();

    iterator_t queryStart = std::find(uri.begin(), uriEnd, '?');

    iterator_t protocolStart = uri.begin();
    iterator_t protocolEnd = std::find(protocolStart, uriEnd, ':');

    if(protocolEnd != uriEnd) {
        std::string prot = &*(protocolEnd);
        if((prot.length() > 3) && (prot.substr(0, 3) == "://")) {
            result.protocol = std::string(protocolStart, protocolEnd);
            protocolEnd += 3;
        }
        else {
            protocolEnd = uri.begin();  // no protocol
        }
    }
    else {
        protocolEnd = uri.begin();  // no protocol
    }

    iterator_t otpTypeStart = protocolEnd;
    iterator_t labelIssuerStart = std::find(otpTypeStart, uriEnd, '/');

    result.otpType = std::string(otpTypeStart, labelIssuerStart);

    iterator_t labelIssuerEnd = std::find(labelIssuerStart, uriEnd, ':');

    if(labelIssuerStart != uriEnd) {
        result.labelIssuer = std::string(labelIssuerStart+1, labelIssuerEnd);
    }
    
    if(labelIssuerEnd != uriEnd) {
        result.labelAccountName = std::string(labelIssuerEnd+1, queryStart);
    }

    std::map<std::string, std::string> queryMap = split_query(std::string(queryStart+1, uri.end()));
    
    auto parameterSearch = queryMap.find("secret");
    if(parameterSearch != queryMap.end()) {
        result.parameters.secretKey = parameterSearch->second;
    }
    
    parameterSearch = queryMap.find("issuer");
    if(parameterSearch != queryMap.end()) {
        result.parameters.issuer = parameterSearch->second;
    }
    
    parameterSearch = queryMap.find("algorithm");
    if(parameterSearch != queryMap.end()) {
        result.parameters.hashAlgorithm = parameterSearch->second;
    }
    
    parameterSearch = queryMap.find("digits");
    if(parameterSearch != queryMap.end()) {
        result.parameters.codeDigits = parameterSearch->second;
    }
    
    parameterSearch = queryMap.find("counter");
    if(parameterSearch != queryMap.end()) {
        result.parameters.counter = parameterSearch->second;
    }
    
    parameterSearch = queryMap.find("period");
    if(parameterSearch != queryMap.end()) {
        result.parameters.stepPeriod = parameterSearch->second;
    }
    
    return result;

}   // Parse

static std::map<std::string, std::string> split_query(const std::string& query) {
    std::map<std::string, std::string> results;

    // Split into key value pairs separated by '&'.
    size_t prev_amp_index = 0;
    while(prev_amp_index != std::string::npos) {
        size_t amp_index = query.find_first_of('&', prev_amp_index);
        if(amp_index == std::string::npos) { 
            amp_index = query.find_first_of(';', prev_amp_index);
        }

        std::string key_value_pair = query.substr(
            prev_amp_index,
            amp_index == std::string::npos ? query.size() - prev_amp_index : amp_index - prev_amp_index);
        prev_amp_index = amp_index == std::string::npos ? std::string::npos : amp_index + 1;

        size_t equals_index = key_value_pair.find_first_of('=');
        if(equals_index == std::string::npos) {
            continue;
        }
        else if(equals_index == 0) {
            std::string value(key_value_pair.begin() + equals_index + 1, key_value_pair.end());
            results[""] = value;
        }
        else {
            std::string key(key_value_pair.begin(), key_value_pair.begin() + equals_index);
            std::string value(key_value_pair.begin() + equals_index + 1, key_value_pair.end());
        results[key] = value;
        }
    }

    return results;
}

std::string deriveUriString(const Uri inputUri){
    std::stringstream outStringStream;
    
    outStringStream << inputUri.protocol
    << "://" << inputUri.otpType 
    << "/" << inputUri.labelIssuer 
    << ":" << inputUri.labelAccountName
    << "?secret=" << inputUri.parameters.secretKey;
    
    if(!(inputUri.parameters.issuer.empty())) {
        outStringStream << "&issuer=" << inputUri.parameters.issuer;
    }
    if(!(inputUri.parameters.hashAlgorithm.empty())) {
        outStringStream << "&algorithm=" << inputUri.parameters.hashAlgorithm;
    }
    if(!(inputUri.parameters.codeDigits.empty())) {
        outStringStream << "&digits=" << inputUri.parameters.codeDigits;
    }
    if(!(inputUri.parameters.counter.empty())) {
        outStringStream << "&counter=" << inputUri.parameters.counter;
    }
    if(!(inputUri.parameters.stepPeriod.empty())) {
        outStringStream << "&period=" << inputUri.parameters.stepPeriod;
    }
    outStringStream << std::endl;
    
    std::string outString = outStringStream.str();
    return outString;
}

