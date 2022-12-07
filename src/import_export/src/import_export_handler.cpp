#include "import_export_handler.h"

#include "filesystem_io.h"
#include "crypto.h"

bool convertToDatafile(const std::string& clearFile, 
                   const std::string& dataFile, 
                   const std::string& passPhrase) {
    std::map<int,Uri> uriMap = readRawDB(clearFile);
    return encryptAndWrite(uriMap, dataFile, passPhrase);
}

bool exportData(std::map<int, Uri> uriMap, const std::string& exportfile) {
    return encryptAndWrite(uriMap, exportfile);
}

bool exportRawData(std::map<int, Uri> uriMap, const std::string& exportfile){
    return decryptAndWrite(uriMap,exportfile);
}
