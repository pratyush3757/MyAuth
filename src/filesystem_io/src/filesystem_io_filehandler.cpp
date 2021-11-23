#include "filesystem_io_filehandler.h"

#include <iostream>
#include <fstream>
#include <vector>

static std::map<int,Uri> processLines(std::vector<std::string> lineVector);
 
std::map<int,Uri> readAuthDB(const std::string filename) {
    std::string line;
//     if(argc != 2) {
//         cerr << "One argument is required." << endl;
//         return 1;
//     }
//     string filename;
    
    std::cout << "* trying to open and read: " << filename << std::endl;
    std::ifstream f (filename);
    
    // After this attempt to open a file, we can safely use perror() only  
    // in case f.is_open() returns False.
    if (!f.is_open()){
        perror(("error while opening file " + filename).c_str());
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
    if (f.bad()) {
        perror(("error while reading file " + filename).c_str());
    }   
        
    f.close();
    
    return processLines(linesVector);
}

static std::map<int,Uri> processLines(std::vector<std::string> lineVector) {
    std::map<int, Uri> uriMap;
    for (int i = 0; auto it : lineVector){
        uriMap[i] = parseUri(it);
        
        i++;
    }
    
    std::cout << "Map created!" << std::endl;
    return uriMap;
}
 
// int main(int argc, char* argv[]) {
// //     readAuthDB("/home/ishu/Desktop/assgn/Auth/supersecretauthdata.dat");
//     return 0;
// }
