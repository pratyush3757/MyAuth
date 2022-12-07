#include "filesystem_io_filehandler.h"
#include "crypto.h"

#include "datatypes_secret.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <utility>

#include <stdlib.h>

static std::map<int, Uri> lineVectorToMap(std::vector<std::string> lineVector);

std::map<int, Uri> readRawDB(const std::string& filename) {
    if(filename.empty()) {      // handle blank filename for creation of new datafile
        std::map<int, Uri> blank;
        return blank;
    }
    
    std::string line;
    
    std::ifstream f(filename);

    if(!f.is_open()) {
        perror(("error while opening file " + filename).c_str());
    }
    
    std::vector<std::string> linesVector;
    while(getline(f, line)) {
        linesVector.push_back(line);
    }
    
    if(f.bad()) {
        perror(("error while reading file " + filename).c_str());
    }   
        
    f.close();
    
    return lineVectorToMap(linesVector);
}

std::map<int, Uri> readAuthDB(const std::string& dataFile, const std::string& passPhrase) {
    std::string line;
    
    std::ifstream f(dataFile);
    
    if(!f.is_open()) {
        perror(("error while opening file " + dataFile).c_str());
        exit(1);
    }
    
    std::string ivString;
    std::string challenge;
    getline(f, ivString);
    getline(f,challenge);
    // Discard both lines as the runtime keys have already been set during authentication.
    
    std::vector<std::string> linesVector;
    while(getline(f, line)) {
        linesVector.push_back(line);
    }
    
    if(f.bad()) {
        perror(("error while reading file " + dataFile).c_str());
        exit(1);
    }   
        
    f.close();
    
    return runtimeEncrypt(lineVectorToMap(linesVector), passPhrase);
}

std::pair<std::string,std::string> readIvAndChallenge(const std::string& dataFile) {
    std::ifstream f(dataFile);
    
    if(!f.is_open()) {
        perror(("error while opening file " + dataFile).c_str());
        exit(1);
    }
    
    std::string ivString;
    std::string challenge;
    getline(f, ivString);
    getline(f,challenge);
    
    if(f.bad()) {
        perror(("error while reading file " + dataFile).c_str());
        exit(1);
    }   
        
    f.close();
    
    return std::make_pair(ivString,challenge);
}

bool statDataFile(const std::string& dataFile) {
    std::ifstream f(dataFile.c_str());
    return f.good();
}

std::pair<bool, std::string> findDataFile() {
    /*
    Data File priority:
         1. ./<project_name>.dat
         2. ~/.config/<project_name>/<project_name>.dat
    */
    const char* homeDir = getenv("HOME");
    const std::string homeConfigPath = std::string(homeDir) + "/.config/authproj/test.dat";
    const std::string currentDirConfigPath = "test.dat";
    std::ifstream f1(currentDirConfigPath);
    if(f1.good()) {
        return std::make_pair(true, currentDirConfigPath);
    }
    else {
        std::ifstream f2(homeConfigPath);
        if(f2.good()){
            return std::make_pair(true, homeConfigPath);
        }
        else {
            return std::make_pair(false, "");
        }
    }
    return std::make_pair(false, "");
}

bool updateDatafile(std::map<int, Uri> uriMap,const std::string& dataFile) {
    return encryptAndWrite(uriMap,dataFile);
}

static std::map<int, Uri> lineVectorToMap(std::vector<std::string> lineVector) {
    std::map<int, Uri> uriMap;
    for(int i = 0; auto it : lineVector) {
        uriMap[i] = parseUriString(it);
        
        i++;
    }
    
    return uriMap;
}
