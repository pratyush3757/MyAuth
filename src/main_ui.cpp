#include "filesystem_io_filehandler.h"
#include "token_totp.h"

#include <ncurses.h>

#include <chrono>

#include <stdio.h>
#include <unistd.h>

int main() {
    
    initscr ();
    
    curs_set (0);
//         while (c < 1000) {
//                 /* Print at row 0, col 0 */
//                 mvprintw (0, 0, "%d", c++);
//                 refresh ();
//                 sleep (1);
//         }
    
    std::map<int,Uri> res = readAuthDB("/home/ishu/Desktop/assgn/Auth/supersecretauthdata");
    
    int codeDigits, stepPeriod;
    std::string hashAlgorithm;
    
    bool flag=true;
    while(flag) {
        for(auto it:res) {
//         std::cout << std::endl << it.first
//         << "\nProtocol: " << it.second.protocol 
//         << "\nOtpType: " << it.second.otpType 
//         << "\nLabel Issuer: " << it.second.labelIssuer 
//         << "\nLabel Accountname: " << it.second.labelAccountName
//         << "\nParameters: "  << std::endl
//         << "\tSecretKey: " << it.second.parameters.secretKey 
//         << "\n\tIssuer: "  << it.second.parameters.issuer 
//         << "\n\tAlgorithm: "  << it.second.parameters.hashAlgorithm
//         << "\n\tDigits: "  << it.second.parameters.codeDigits
//         << "\n\tCounter: "  << it.second.parameters.counter
//         << "\n\tPeriod: "  << it.second.parameters.stepPeriod << std::endl;

            const auto p1 = std::chrono::system_clock::now();
            long long int time = std::chrono::duration_cast<std::chrono::seconds>(
                    p1.time_since_epoch()).count();
                    
            codeDigits = (it.second.parameters.codeDigits=="") ? 
                            6 : stoi(it.second.parameters.codeDigits);
            stepPeriod = (it.second.parameters.stepPeriod=="") ? 
                            30 : stoi(it.second.parameters.stepPeriod);
            hashAlgorithm = (it.second.parameters.hashAlgorithm=="") ?
                            "SHA1" : it.second.parameters.hashAlgorithm;
                            
            std::string totp = computeTotpFromUri(it.second.parameters.secretKey,time,codeDigits,hashAlgorithm,stepPeriod);
            std::string life = std::to_string(computeTotpLifetime(time,stepPeriod));
            
            std::string line = it.second.labelIssuer + ": " + it.second.labelAccountName 
                                + "\n\t" + totp + " [ " + life + " ]\n\n";
            printw(line.c_str());
            refresh();
            
//         std::cout << "TOTP: "
//         << computeTotpFromUri(it.second.parameters.secretKey,time,codeDigits,hashAlgorithm,stepPeriod)
//         << "\nLife: " << computeTotpLifetime(time,stepPeriod) << "\nTime: " << time <<std::endl;
//         std::cout << computeTotpFromUri("WRN3PQX5UQXQVNQR",1297553958,6,"SHA1",30)<< std::endl;
        }
        sleep(1);
        clear();
    }
    /* End ncurses mode */
    endwin();
    
    return 0;
}


// int showOutput() {
//         /* compile with gcc -lncurses file.c */
//         int c = 0;
//         /* Init ncurses mode */
//         initscr ();
//         /* Hide cursor */
//         curs_set (0);
//         while (c < 1000) {
//                 /* Print at row 0, col 0 */
//                 mvprintw (0, 0, "%d", c++);
//                 refresh ();
//                 sleep (1);
//         }
//         /* End ncurses mode */
//         endwin();
//         return 0;
// }
