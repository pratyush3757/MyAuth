#include "datatypes_uri.h"
#include "datatypes_flags.h"
#include "filesystem_io.h"
#include "fs_io_crypto.h"
#include "token.h"

#include <ncurses.h>

#include <chrono>
#include <iostream>
#include <optional>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

std::map<int, Uri> fileop(int argc, char** argv);
std::map<int, Uri> parseOptions(int argc, char** argv);

SecretKeyFlags runtimeFlag = SecretKeyFlags::base32_encoded_secretKey;

int main(int argc, char** argv) {
    
    std::map<int, Uri> res = parseOptions(argc, argv);
//     int xyz = 0;
    initscr();
    
    curs_set(0);

//     std::string decryptedFile = argv[3];
//     std::map<int, Uri> res2 = readAuthDB(decryptedFile);
    
    if(res.empty()) {
        endwin();
        curs_set(1);
        std::cerr << "[Warning] Datafile is Empty. Exiting..." << std::endl;
        exit(0);
    }
    
    int codeDigits, stepPeriod;
    std::string hashAlgorithm;
    
    bool flag = true;
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
                            
            std::string totp = computeTotp(it.second.parameters.secretKey, time, codeDigits, hashAlgorithm, stepPeriod,runtimeFlag);
            std::string life = std::to_string(computeTotpLifetime(time, stepPeriod));
            
            std::string line = it.second.labelIssuer + ": " + it.second.labelAccountName 
                                + "\n\t" + totp + " [ " + life + " ]\n\n";
            printw("%s", line.c_str());
            refresh();
            
        }
        sleep(1);
        clear();
    }
    /* End ncurses mode */
    endwin();
    
    return 0;
}

std::map<int, Uri> fileop(int argc, char** argv) {
    std::map<int, Uri> blankMap;
    if(argc == 5) {

        char *action = argv[1];
        const std::string sourceFileName = argv[2];
        const std::string targetFileName = argv[3];
        const std::string passPhrase = argv[4];
        
        if(strcmp(action, "e") == 0) {
            importFile(sourceFileName, targetFileName, passPhrase);
//             return a;
        }
        else if(strcmp(action, "d") == 0) {
            runtimeFlag = SecretKeyFlags::encrypted_secretKey;
            if(authenticatePassPhrase(sourceFileName, passPhrase)){
                return readAuthDB(sourceFileName, passPhrase);
            }
            else {
                return blankMap;
            }
        }
        return blankMap;
    }
    else {
        std::cout << "Missing/Invalid params" << std::endl;
        exit(1);
//         return a;
    }
}

std::map<int, Uri> parseOptions(int argc, char** argv) {
    int i;
    extern char* optarg;
    
    std::string clearfile;
    std::string passPhrase;
    std::string datafile;
    std::string defaultConfigPath = "test.dat";
    int encryptFlag = 0, passFlag = 0, dataFileFlag = 0, err = 0;
    static char usage[] = "usage: %s \
    [-f <datafile> | (-e <clearfile> -f <datafile>)] [-p <passphrase>]\n";
    
    while((i = getopt(argc,argv,"e:f:p:")) != -1) {
        switch(i){
            case 'e':
                encryptFlag = 1;
                clearfile.assign(optarg);
                break;
            case 'f':
                dataFileFlag = 1;
                datafile.assign(optarg);
                break;
            case 'p':
                passFlag = 1;
                passPhrase.assign(optarg);
                break;
            case '?':
                err = 1;
                break;
        }
    }
    
    if(err) {
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }
    if(passFlag == 0) {
        std::cout << "Enter the passphrase: ";
        std::cin >> passPhrase;
        passFlag = 1;
    }
    if(dataFileFlag == 0) {
        std::pair<bool,std::string> tempPair = findDataFile();
        if(tempPair.first == false) {
            std::cerr << "[Error] Datafile not found" << std::endl;
            std::cout << "creating new file";
//             create new file by importFile(blankFile,defaultConfigPath,passPhrase);
            importFile("", defaultConfigPath, passPhrase);
            datafile = defaultConfigPath;
        }
        else {
            std::cout << "Datafile found: " << tempPair.second << std::endl;
            datafile = tempPair.second;
            dataFileFlag = 1;
        }
    }
    if(encryptFlag == 1) {
        if(dataFileFlag == 0) {
            std::cerr << "[Error] Datafile not provided, using current directory. Saving to: " 
            << defaultConfigPath << std::endl;
        }
        
        if(statDataFile(clearfile)) {
            importFile(clearfile, datafile, passPhrase);
        }
        else {
            std::cerr << "[Error] Given Clearfile does not exist, please provide valid <clearfile>." << std::endl;
            exit(1);
        }
    }
    
    runtimeFlag = SecretKeyFlags::encrypted_secretKey;
    if(dataFileFlag == 1 && authenticatePassPhrase(datafile, passPhrase)) {
        return readAuthDB(datafile, passPhrase);
    }
    else {
        exit(1);
    }
}
