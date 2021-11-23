#include "filesystem_io_filehandler.h"
#include "fs_io_crypto_filehandler.h"
#include "token_totp.h"

#include <ncurses.h>

#include <chrono>
#include <iostream>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void fileop(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    
    fileop(argc,argv);
    initscr ();
    
    curs_set (0);

    std::string decryptedFile = argv[3];
    std::map<int,Uri> res = readAuthDB(decryptedFile);
    
    int codeDigits, stepPeriod;
    std::string hashAlgorithm;
    
    bool flag=true;
    while(flag) {
        for(auto it:res) {

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
            
        }
        sleep(1);
        clear();
    }
    /* End ncurses mode */
    endwin();
    
    return 0;
}

void fileop(int argc, char* argv[]){
    if (argc == 5){

        char * action = argv[1];
        const char *sourceFileName = argv[2];
        const char *targetFileName = argv[3];
        const char *passPhrase = argv[4];
        
        if (strcmp(action, "e") == 0){
            EncryptFile(sourceFileName,targetFileName,passPhrase);
        }
        else if (strcmp(action, "d") == 0){
            DecryptFile(sourceFileName,targetFileName,passPhrase);
        }
    }
    else {
        std::cout << "Missing/Invalid params" << std::endl;
        exit(1);
    }
}
