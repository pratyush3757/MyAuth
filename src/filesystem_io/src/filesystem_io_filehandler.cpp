#include "filesystem_io_filehandler.h"
#include "filesystem_io_uri.h"
#include "fs_io_crypto.h"

#include "datatypes_secret.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <utility>

#include <stdlib.h>

static std::map<int, Uri> processLines(std::vector<std::string> lineVector);

std::map<int, Uri> readRawDB(const std::string& filename) {
    if(filename.empty()) {      // handle blank filename for creation of new datafile
        std::map<int, Uri> blank;
        return blank;
    }
    
    std::string line;
//     if(argc != 2) {
//         cerr << "One argument is required." << endl;
//         return 1;
//     }
//     string filename;
    
    std::cout << "* trying to open and read: " << filename << std::endl;
    std::ifstream f(filename);
    
    // After this attempt to open a file, we can safely use perror() only  
    // in case f.is_open() returns False.
    if(!f.is_open()) {
        perror(("error while opening file " + filename).c_str());
        exit(1);
    }
    
    // Read the file via std::getline(). Rules obeyed:
    //   - first the I/O operation, then error check, then data processing
    //   - failbit and badbit prevent data processing, eofbit does not
    std::vector<std::string> linesVector;
    while(getline(f, line)) {
        linesVector.push_back(line);
    }
    
    // Only in case of set badbit we are sure that errno has been set in
    // the current context. Use perror() to print error details.
    if(f.bad()) {
        perror(("error while reading file " + filename).c_str());
        exit(1);
    }   
        
    f.close();
    
    return processLines(linesVector);
}

std::map<int, Uri> readAuthDB(const std::string& filename, const std::string& passPhrase) {
    std::string line;
    
    std::cout << "* trying to open and read: " << filename << std::endl;
    std::ifstream f(filename);
    
    // After this attempt to open a file, we can safely use perror() only  
    // in case f.is_open() returns False.
    if(!f.is_open()) {
        perror(("error while opening file " + filename).c_str());
        exit(1);
    }
    
    std::string ivString;
    std::string challenge;
    getline(f, ivString);
    getline(f,challenge);
//     RuntimeKeys fileKeys(passPhrase,ivString);
    
    // Read the file via std::getline(). Rules obeyed:
    //   - first the I/O operation, then error check, then data processing
    //   - failbit and badbit prevent data processing, eofbit does not
    std::vector<std::string> linesVector;
    while(getline(f, line)) {
        linesVector.push_back(line);
    }
    
    // Only in case of set badbit we are sure that errno has been set in
    // the current context. Use perror() to print error details.
    if(f.bad()) {
        perror(("error while reading file " + filename).c_str());
        exit(1);
    }   
        
    f.close();
    
    return runtimeEncrypt(processLines(linesVector), passPhrase);
}

static std::map<int, Uri> processLines(std::vector<std::string> lineVector) {
    std::map<int, Uri> uriMap;
    for(int i = 0; auto it : lineVector) {
        uriMap[i] = parseUri(it);
        
        i++;
    }
    
    std::cout << "Map created!" << std::endl;
    return uriMap;
}

bool statDataFile(const std::string& dataFile) {
    std::ifstream f(dataFile.c_str());
    return f.good();
}

std::pair<bool, std::string> findDataFile() {
    /*
    Data File priority:
         1. ~/.config/<project_name>/<project_name>.dat
         2. ./<project_name>.dat
    */
    const char* homeDir = getenv("HOME");
    const std::string homeConfigPath = std::string(homeDir) + "/.config/authproj/test.dat";
    std::ifstream f1(homeConfigPath);
    if(f1.good()) {
        return std::make_pair(true, homeConfigPath);
    }
    else {
        const std::string currentDirConfigPath = "test.dat";
        std::ifstream f2(currentDirConfigPath);
        if(f2.good()){
            return std::make_pair(true, currentDirConfigPath);
        }
        else {
            return std::make_pair(false, "");
        }
    }
    return std::make_pair(false, "");
}

// int main(int argc, char* argv[]) {
// //     readAuthDB("/home/ishu/Desktop/assgn/Auth/supersecretauthdata.dat");
//     return 0;
// }
