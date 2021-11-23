#include <bits/stdc++.h>
#include <chrono>

#include "filesystem_io_filehandler.h"
#include "token_totp.h"

int main() {
    
    
    std::map<int,Uri> res = readAuthDB("/home/ishu/Desktop/assgn/Auth/supersecretauthdata.dat");
    
    for(auto it:res) {
        std::cout << std::endl << it.first
        << "\nProtocol: " << it.second.protocol 
        << "\nOtpType: " << it.second.otpType 
        << "\nLabel Issuer: " << it.second.labelIssuer 
        << "\nLabel Accountname: " << it.second.labelAccountName
        << "\nParameters: "  << std::endl
        << "\tSecretKey: " << it.second.parameters.secretKey 
        << "\n\tIssuer: "  << it.second.parameters.issuer 
        << "\n\tAlgorithm: "  << it.second.parameters.hashAlgorithm
        << "\n\tDigits: "  << it.second.parameters.codeDigits
        << "\n\tCounter: "  << it.second.parameters.counter
        << "\n\tPeriod: "  << it.second.parameters.stepPeriod << std::endl;
        
        const auto p1 = std::chrono::system_clock::now();
        long long int time = std::chrono::duration_cast<std::chrono::seconds>(
                   p1.time_since_epoch()).count();
                   
        const int codeDigits = (it.second.parameters.codeDigits=="") ? 
                                6 : stoi(it.second.parameters.codeDigits);
        const int stepPeriod = (it.second.parameters.stepPeriod=="") ? 
                                30 : stoi(it.second.parameters.stepPeriod);
        const std::string hashAlgorithm = (it.second.parameters.hashAlgorithm=="") ?
                                "SHA1" : it.second.parameters.hashAlgorithm;
                                
        std::cout << "TOTP: "
        << computeTotpFromUri(it.second.parameters.secretKey,time,codeDigits,hashAlgorithm,stepPeriod)
        << "\nLife: " << computeTotpLifetime(time,stepPeriod) << "\nTime: " << time <<std::endl;
    }
//     std::cout << computeTotpFromUri("WRN3PQX5UQXQVNQR",1297553958,6,"SHA1",30)<< std::endl;
    
    return 0;
}
