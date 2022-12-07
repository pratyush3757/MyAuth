#ifndef _CRYPTO_FILEHANDLER_H_
#define _CRYPTO_FILEHANDLER_H_

#include "datatypes_uri.h"

#include <string>
#include <map>

bool encryptAndWrite(std::map<int, Uri> uriMap, const std::string& dataFile);

bool encryptAndWrite(std::map<int, Uri> uriMap, 
                     const std::string& dataFile, 
                     const std::string& passPhrase);

bool decryptAndWrite(std::map<int, Uri> uriMap, const std::string& exportFile);

#endif
